import asyncio
import unittest
from datetime import datetime, timezone

from tortoise import Tortoise

import main
from db import Company, Domain, Finding, Scan

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
NOISE = "[MEDIUM] Path discovered: /wp-json/ (HTTP 200, 406975 bytes)"
REAL = "[CRITICAL] Path discovered: /wp-config.php.old (HTTP 200, 3689 bytes)"


def run(coro_fn):
    async def runner():
        await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["db"]})
        await Tortoise.generate_schemas()
        try:
            return await coro_fn()
        finally:
            await Tortoise.close_connections()
    return asyncio.run(runner())


async def _scan_with(findings, host="app.example.com"):
    company = await Company.create(name="acme")
    dom = await Domain.create(domain="example.com", company_id=company.id)
    modules = {"smart_fuzz": {"risk": "critical", "findings": findings}}
    card = main._overall_score(modules)
    result = {"domain": host, "kind": "host", "modules": modules, "scorecard": card,
              "findings": [{"module": "smart_fuzz", "finding": t, "risk": "critical", "category": "exposure"}
                           for t in findings]}
    scan = await Scan.create(id="s1", domain_id=dom.id, kind="host", scan_target=host, status="completed",
                             started_at=NOW, completed_at=NOW, scorecard=card, result=result)
    return dom, scan


async def _finding(dom, text, status, host="app.example.com"):
    return await Finding.create(
        domain_id=dom.id, fingerprint=main._finding_fingerprint(host, "smart_fuzz", text), module="smart_fuzz",
        text=text, host=host, risk="critical", category="exposure", status=status,
        first_seen_scan_id="s1", last_seen_scan_id="s1", first_seen_at=NOW, last_seen_at=NOW)


class RescoreTests(unittest.TestCase):
    def test_false_positive_and_accepted_lines_stop_counting(self):
        async def go():
            dom, scan = await _scan_with([REAL, NOISE])
            before = scan.scorecard["findings_by_severity"]["medium"] + scan.scorecard["findings_by_severity"]["critical"]
            await _finding(dom, REAL, "accepted")
            await _finding(dom, NOISE, "false_positive")
            changed = await main._rescore_scan(await Scan.get(id="s1"))
            fresh = await Scan.get(id="s1")
            return before, changed, fresh
        before, changed, fresh = run(go)
        self.assertTrue(changed)
        self.assertEqual(fresh.scorecard["findings_by_severity"]["critical"], 0)
        self.assertEqual(fresh.scorecard["overall_risk"], "low")
        self.assertEqual(fresh.result["scorecard"], fresh.scorecard)

    def test_open_findings_leave_the_score_alone(self):
        async def go():
            dom, _ = await _scan_with([REAL, NOISE])
            await _finding(dom, REAL, "open")
            await main._rescore_scan(await Scan.get(id="s1"))     # first pass relabels the lines
            return await main._rescore_scan(await Scan.get(id="s1"))
        self.assertFalse(run(go))

    def test_reopening_restores_the_score(self):
        async def go():
            dom, _ = await _scan_with([REAL, NOISE])
            noise = await _finding(dom, NOISE, "false_positive")
            await main._rescore_scan(await Scan.get(id="s1"))
            mid = (await Scan.get(id="s1")).scorecard["score"]
            await Finding.filter(id=noise.id).update(status="open")
            await main._rescore_scan(await Scan.get(id="s1"))
            return mid, (await Scan.get(id="s1")).scorecard["score"]
        mid, end = run(go)
        self.assertGreaterEqual(mid, end)

    def test_lines_get_their_own_severity_label(self):
        async def go():
            dom, _ = await _scan_with([REAL, NOISE])
            await _finding(dom, NOISE, "false_positive")
            await main._rescore_scan(await Scan.get(id="s1"))
            return {f["finding"][:8]: f["risk"] for f in (await Scan.get(id="s1")).result["findings"]}
        risks = run(go)
        self.assertEqual(risks, {"[CRITICA": "critical", "[MEDIUM]": "medium"})


class HideDismissedTests(unittest.TestCase):
    def test_report_hides_accepted_and_false_positive_but_not_open(self):
        async def go():
            dom, scan = await _scan_with([REAL, NOISE, "[MEDIUM] Path discovered: /license.txt (HTTP 200, 19903 bytes)"])
            await _finding(dom, NOISE, "false_positive")
            await _finding(dom, REAL, "open")
            await _finding(dom, "[MEDIUM] Path discovered: /license.txt (HTTP 200, 19903 bytes)", "accepted")
            return scan.result, await main._hide_dismissed(scan.result, dom.id)
        original, shaped = run(go)
        self.assertEqual([f["finding"] for f in shaped["findings"]], [REAL])
        self.assertEqual(shaped["dismissed_findings"], 2)
        self.assertEqual(len(original["findings"]), 3)            # the stored result is untouched

    def test_nothing_dismissed_returns_the_result_as_is(self):
        async def go():
            dom, scan = await _scan_with([REAL, NOISE])
            await _finding(dom, REAL, "open")
            return scan.result, await main._hide_dismissed(scan.result, dom.id)
        original, shaped = run(go)
        self.assertIs(shaped, original)

    def test_size_jitter_does_not_resurface_a_dismissed_finding(self):
        async def go():
            dom, scan = await _scan_with(["[MEDIUM] Path discovered: /wp-json/ (HTTP 200, 411111 bytes)"])
            await _finding(dom, NOISE, "false_positive")          # decided when the size was 406975
            return await main._hide_dismissed(scan.result, dom.id)
        shaped = run(go)
        self.assertEqual(shaped["findings"], [])


if __name__ == "__main__":
    unittest.main()

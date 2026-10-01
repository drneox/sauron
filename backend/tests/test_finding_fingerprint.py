import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from tortoise import Tortoise

import finding_fingerprint as ff
from db import AppSetting, Company, Domain, Finding

T0 = datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)


def run(coro_fn):
    async def runner():
        await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["db"]})
        await Tortoise.generate_schemas()
        try:
            return await coro_fn()
        finally:
            await Tortoise.close_connections()
    return asyncio.run(runner())


class NormalizeTests(unittest.TestCase):
    def test_strips_severity_directed_marker_and_size(self):
        a = "[HIGH] Path discovered [LLM-directed]: /wp-json/wp/v2/pages (HTTP 200, 1064354 bytes)"
        b = "[MEDIUM] Path discovered: /wp-json/wp/v2/pages (HTTP 200, 1064360 bytes)"
        self.assertEqual(ff.normalize_text(a), ff.normalize_text(b))
        self.assertEqual(ff.normalize_text(a), "Path discovered: /wp-json/wp/v2/pages (HTTP 200)")

    def test_real_differences_remain(self):
        a = ff.fingerprint("h", "smart_fuzz", "[HIGH] Path discovered: /a (HTTP 200, 10 bytes)")
        self.assertNotEqual(a, ff.fingerprint("h", "smart_fuzz", "[HIGH] Path discovered: /b (HTTP 200, 10 bytes)"))
        self.assertNotEqual(a, ff.fingerprint("h2", "smart_fuzz", "[HIGH] Path discovered: /a (HTTP 200, 10 bytes)"))
        self.assertNotEqual(a, ff.fingerprint("h", "exposed_files", "[HIGH] Path discovered: /a (HTTP 200, 10 bytes)"))
        self.assertNotEqual(a, ff.fingerprint("h", "smart_fuzz", "[HIGH] Path discovered: /a (HTTP 403, 10 bytes)"))

    def test_idempotent(self):
        t = "[HIGH] x [LLM-directed] (HTTP 200, 5 bytes)"
        self.assertEqual(ff.normalize_text(ff.normalize_text(t)), ff.normalize_text(t))


async def _mk(domain, text, days, status="open", fixed=None, host="a.example.com", fp=None):
    return await Finding.create(
        domain_id=domain.id, fingerprint=fp or f"old-{days}-{text[:8]}", module="smart_fuzz", text=text,
        host=host, risk="high", category="vulnerability", status=status,
        first_seen_scan_id="s0", last_seen_scan_id=f"s{days}",
        first_seen_at=T0 + timedelta(days=days), last_seen_at=T0 + timedelta(days=days),
        fixed_at=fixed)


class RefingerprintTests(unittest.TestCase):
    def test_size_variants_merge_into_one_keeping_earliest_and_latest_state(self):
        async def go():
            c = await Company.create(name="acme")
            d = await Domain.create(domain="a.example.com", company_id=c.id)
            await _mk(d, "[HIGH] Path discovered: /x.log (HTTP 200, 100 bytes)", 0, "fixed", fixed=T0 + timedelta(days=1))
            await _mk(d, "[HIGH] Path discovered [LLM-directed]: /x.log (HTTP 200, 200 bytes)", 5)
            await _mk(d, "[HIGH] Path discovered: /y.log (HTTP 200, 5 bytes)", 2)
            stats = await ff.refingerprint_all()
            self.assertEqual(stats["merged"], 1)
            rows = await Finding.filter(domain_id=d.id).order_by("id")
            self.assertEqual(len(rows), 2)
            x = [r for r in rows if "/x.log" in r.text][0]
            self.assertEqual(x.status, "open")
            self.assertEqual(x.first_seen_at, T0)
            self.assertEqual(x.fingerprint, ff.fingerprint("a.example.com", "smart_fuzz", x.text))
        run(go)

    def test_accepted_survives_merge(self):
        async def go():
            c = await Company.create(name="acme")
            d = await Domain.create(domain="a.example.com", company_id=c.id)
            await _mk(d, "[HIGH] P: /x (HTTP 200, 1 bytes)", 0, "accepted")
            await _mk(d, "[HIGH] P: /x (HTTP 200, 2 bytes)", 3)
            await ff.refingerprint_all()
            rows = await Finding.filter(domain_id=d.id)
            self.assertEqual([r.status for r in rows], ["accepted"])
        run(go)

    def test_same_text_on_different_hosts_stays_separate(self):
        async def go():
            c = await Company.create(name="acme")
            d = await Domain.create(domain="example.com", company_id=c.id)
            await _mk(d, "[HIGH] P: /x (HTTP 200, 1 bytes)", 0, host="a.example.com")
            await _mk(d, "[HIGH] P: /x (HTTP 200, 1 bytes)", 1, host="b.example.com")
            stats = await ff.refingerprint_all()
            self.assertEqual(stats["merged"], 0)
            self.assertEqual(await Finding.filter(domain_id=d.id).count(), 2)
        run(go)

    def test_ensure_current_runs_once(self):
        async def go():
            c = await Company.create(name="acme")
            d = await Domain.create(domain="a.example.com", company_id=c.id)
            await _mk(d, "[HIGH] P: /x (HTTP 200, 1 bytes)", 0)
            self.assertIsNotNone(await ff.ensure_current())
            self.assertIsNone(await ff.ensure_current())
            row = await AppSetting.get(key="finding_fingerprint_version")
            self.assertEqual(row.value, ff.FINGERPRINT_VERSION)
        run(go)


if __name__ == "__main__":
    unittest.main()

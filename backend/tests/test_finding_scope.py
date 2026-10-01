import unittest
from types import SimpleNamespace

from finding_scope import covered_hosts, modules_that_ran, stale_findings


def f(host, module="smart_fuzz", fp="x"):
    return SimpleNamespace(host=host, module=module, fingerprint=fp)


FULL = {"domain": "example.com", "modules": {
    "smart_fuzz": {"status": "ok"}, "headers": {"status": "ok"},
    "nuclei": {"status": "timed_out"}, "breach": {"status": "skipped"},
    "subdomain_eval": {"status": "ok", "evaluated": [
        {"subdomain": "app.example.com", "alive": True},
        {"subdomain": "dead.example.com", "alive": False}]},
}}


class SweepScopeTests(unittest.TestCase):
    def test_full_scan_does_not_close_findings_of_hosts_it_never_probed(self):
        # The incident: a still-exposed file on a subdomain was auto-closed by
        # the apex's daily full scan, which never requests that host.
        stale = stale_findings([f("carreras.example.com", fp="wp-config")], set(), FULL, "example.com")
        self.assertEqual(stale, [])

    def test_full_scan_still_closes_its_own_apex_findings(self):
        stale = stale_findings([f("example.com", fp="gone")], set(), FULL, "example.com")
        self.assertEqual([x.fingerprint for x in stale], ["gone"])

    def test_findings_still_seen_are_never_closed(self):
        self.assertEqual(stale_findings([f("example.com", fp="still")], {"still"}, FULL, "example.com"), [])

    def test_hosts_evaluated_alive_inline_are_covered_dead_ones_are_not(self):
        self.assertEqual(covered_hosts(FULL, "example.com"), {"example.com", "app.example.com"})

    def test_a_host_scan_closes_what_it_rechecked_on_its_own_host(self):
        # Without this a fix on a subdomain would never be noticed.
        host_scan = {"domain": "carreras.example.com", "modules": {"smart_fuzz": {"status": "ok"}}}
        stale = stale_findings([f("carreras.example.com", fp="fixed-now"), f("example.com", fp="other-host")],
                               set(), host_scan, "example.com")
        self.assertEqual([x.fingerprint for x in stale], ["fixed-now"])

    def test_unknown_is_not_gone_modules_that_failed_keep_their_findings(self):
        host = "example.com"
        candidates = [f(host, "nuclei"), f(host, "breach"), f(host, "headers")]
        self.assertEqual([x.module for x in stale_findings(candidates, set(), FULL, "example.com")], ["headers"])

    def test_a_waf_truncated_fuzz_is_a_lower_bound_not_a_clean_bill(self):
        res = {"domain": "example.com", "modules": {"smart_fuzz": {"status": "ok", "waf_blocked": True}}}
        self.assertEqual(modules_that_ran(res), set())

    def test_module_scan_only_covers_the_modules_it_ran(self):
        res = {"domain": "example.com", "modules": {"exposed": {"status": "ok"}}}
        stale = stale_findings([f("example.com", "exposed"), f("example.com", "headers")], set(), res, "example.com")
        self.assertEqual([x.module for x in stale], ["exposed"])

    def test_legacy_rows_without_a_host_count_as_the_apex(self):
        self.assertEqual(len(stale_findings([f(None, fp="old")], set(), FULL, "example.com")), 1)
        host_scan = {"domain": "sub.example.com", "modules": {"smart_fuzz": {"status": "ok"}}}
        self.assertEqual(stale_findings([f(None, fp="old")], set(), host_scan, "example.com"), [])

    def test_agent_findings_only_close_when_the_agent_finished_ok(self):
        res = {"domain": "example.com", "modules": {}, "agent_status": "error"}
        self.assertEqual(stale_findings([f("example.com", "agent")], set(), res, "example.com"), [])
        res["agent_status"] = "ok"
        self.assertEqual(len(stale_findings([f("example.com", "agent")], set(), res, "example.com")), 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from main import (
    _agent_finding_evidence,
    _breach_evidence,
    _finding_evidence,
    _finding_host,
    _js_secrets_evidence,
    _match_path_entry,
    _path_evidence,
)


class BreachEvidenceTests(unittest.TestCase):
    def test_leakcheck_line_pulls_source_and_fields(self):
        mod = {"leakcheck": {"found": 2, "sources": [{"name": "Stealer Logs"}],
                             "fields": ["username", "password", "origin"]}}
        out = _breach_evidence("LeakCheck: 2 records found across Stealer Logs", mod)
        self.assertEqual(out["source"], "Stealer Logs")
        self.assertEqual(out["leaked_fields"], "username, password, origin")

    def test_breach_line_matches_by_title(self):
        mod = {"breaches": [{"title": "Acme2019", "breach_date": "2019-05-01", "pwn_count": 12345}]}
        out = _breach_evidence("Breach 'Acme2019' (2019-05-01): Emails, Passwords", mod)
        self.assertEqual(out["breach_date"], "2019-05-01")
        self.assertEqual(out["records"], "12,345")

    def test_combo_line_pulls_a_sample(self):
        mod = {"combo_samples": ["user@example.com:REDACTED"]}
        out = _breach_evidence("42 email:password combos found in combo lists for this domain", mod)
        self.assertIn("user@example.com", out["sample"])

    def test_unrelated_line_yields_nothing(self):
        self.assertIsNone(_breach_evidence("12 email address(es) discovered across all sources", {}))


class PathEvidenceTests(unittest.TestCase):
    def test_matches_the_path_named_in_the_text(self):
        entries = [{"path": "/wp-config.php.old", "status": 200, "size": 3689, "evidence": "<?php define("}]
        match = _match_path_entry("[CRITICAL] Path discovered: /wp-config.php.old (HTTP 200, 3689 bytes)", entries)
        self.assertEqual(match["size"], 3689)

    def test_path_evidence_end_to_end(self):
        mod = {"paths_found": [{"path": "/wp-config.php.old", "status": 200, "size": 3689,
                                "evidence": "<?php define( 'WP_CACHE', true );"}]}
        out = _path_evidence("[CRITICAL] Path discovered: /wp-config.php.old (HTTP 200, 3689 bytes)", mod, ("paths_found",))
        self.assertEqual(out["http_status"], 200)
        self.assertEqual(out["size_bytes"], 3689)
        self.assertIn("WP_CACHE", out["snippet"])

    def test_no_matching_path_yields_none(self):
        mod = {"paths_found": [{"path": "/other", "status": 200, "size": 1}]}
        self.assertIsNone(_path_evidence("Path discovered: /missing (HTTP 200, 1 bytes)", mod, ("paths_found",)))


class FindingEvidenceDispatchTests(unittest.TestCase):
    def test_unknown_module_yields_none(self):
        self.assertIsNone(_finding_evidence("dns", "Zone transfer allowed", {"modules": {}}))

    def test_a_crashing_rule_is_swallowed(self):
        result = {"modules": {"breach": {"breaches": "not-a-list"}}}
        self.assertIsNone(_finding_evidence("breach", "Breach 'X' (d): y", result))



class JsSecretsEvidenceTests(unittest.TestCase):
    def test_pulls_endpoints_and_cloud_hosts_as_lists(self):
        mod = {
            "endpoints": [{"path": "/api/v1/users", "source": "webpack"}, {"path": "/api/v1/orders", "source": "webpack"}],
            "hosts": [{"host": "storage.googleapis.com", "kind": "cloud"}, {"host": "dev.internal.example.com", "kind": "internal-env"}],
        }
        out = _js_secrets_evidence("JS bundle exposes 2 API endpoints and 1 cloud gateway hosts", mod)
        self.assertEqual(out["endpoints"], ["/api/v1/users", "/api/v1/orders"])
        self.assertEqual(out["cloud_hosts"], ["storage.googleapis.com"])

    def test_unrelated_line_yields_nothing(self):
        self.assertIsNone(_js_secrets_evidence("2 critical secret(s) found in JS files (API keys, credentials)", {}))


class AgentFindingEvidenceTests(unittest.TestCase):
    def _result(self, tool, target, finding_text, evidence_source):
        return {
            "agent_steps": [{
                "tool": tool, "target": target,
                "new_findings": [finding_text],
                "evidence_source": evidence_source,
            }],
        }

    def test_mine_js_tool_reuses_the_js_secrets_rule(self):
        text = "JS bundle exposes 1 API endpoints and 1 cloud gateway hosts"
        result = self._result("mine_js", "app.example.com", text, {
            "endpoints": [{"path": "/api/secret", "source": "webpack"}],
            "hosts": [{"host": "bucket.s3.amazonaws.com", "kind": "cloud"}],
        })
        out = _agent_finding_evidence(f"[mine_js] {text}", result)
        self.assertEqual(out["endpoints"], ["/api/secret"])
        self.assertEqual(out["cloud_hosts"], ["bucket.s3.amazonaws.com"])

    def test_fuzz_paths_tool_reuses_the_path_rule(self):
        text = "[CRITICAL] Path discovered: /backup.zip (HTTP 200, 900 bytes)"
        result = self._result("fuzz_paths", "app.example.com", text,
                              {"paths_found": [{"path": "/backup.zip", "status": 200, "size": 900}]})
        out = _agent_finding_evidence(f"[fuzz_paths] {text}", result)
        self.assertEqual(out["http_status"], 200)

    def test_unmatched_step_yields_none(self):
        self.assertIsNone(_agent_finding_evidence("[mine_js] something else entirely", self._result("mine_js", "x", "other", {})))

    def test_non_agent_tagged_text_yields_none(self):
        self.assertIsNone(_agent_finding_evidence("No brackets here", {"agent_steps": []}))

    def test_finding_host_prefers_the_step_target(self):
        text = "JS bundle exposes 1 API endpoints and 0 cloud gateway hosts"
        result = self._result("mine_js", "sub.example.com", text, {})
        self.assertEqual(_finding_host("agent", f"[mine_js] {text}", "example.com", result), "sub.example.com")

    def test_finding_host_falls_back_to_scan_target_when_step_is_unmatched(self):
        result = {"agent_steps": []}
        self.assertEqual(_finding_host("agent", "[mine_js] anything", "example.com", result), "example.com")


if __name__ == "__main__":
    unittest.main()

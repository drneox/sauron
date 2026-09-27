import unittest
from unittest import mock

from modules import agent_scan
from modules.agent_scan import _AgentState


class AgentApexDuplicationGuardTests(unittest.TestCase):
    def test_dedicated_tool_is_skipped_when_its_module_already_ran_on_the_apex(self):
        state = _AgentState("example.com", set(), {"js_secrets"})
        with mock.patch.object(agent_scan.js_secrets, "run") as run:
            out = state.run_tool("mine_js", {"domain": "example.com", "reasoning": "x"})
        run.assert_not_called()
        self.assertEqual(out["status"], "skipped")
        self.assertIn("js_secrets", out["reason"])

    def test_same_tool_on_a_subdomain_is_not_skipped(self):
        # A subdomain the deterministic scan never touched still needs real work.
        state = _AgentState("example.com", set(), {"js_secrets"})
        with mock.patch.object(agent_scan.js_secrets, "run", return_value={"status": "ok", "endpoints": []}) as run:
            out = state.run_tool("mine_js", {"domain": "app.example.com", "reasoning": "x"})
        run.assert_called_once_with("app.example.com")
        self.assertNotEqual(out.get("status"), "skipped")

    def test_tool_runs_when_its_module_did_not_run_deterministically(self):
        state = _AgentState("example.com", set(), set())
        with mock.patch.object(agent_scan.js_secrets, "run", return_value={"status": "ok", "endpoints": []}) as run:
            out = state.run_tool("mine_js", {"domain": "example.com", "reasoning": "x"})
        run.assert_called_once_with("example.com")
        self.assertNotEqual(out.get("status"), "skipped")

    def test_probe_sensitive_files_needs_both_underlying_modules_covered(self):
        # Only "exposed" ran deterministically — admin_discovery would still add something.
        state = _AgentState("example.com", set(), {"exposed"})
        self.assertFalse(state._already_covered("example.com", "probe_sensitive_files"))
        state2 = _AgentState("example.com", set(), {"exposed", "admin"})
        self.assertTrue(state2._already_covered("example.com", "probe_sensitive_files"))

    def test_a_tool_with_no_deterministic_counterpart_is_never_gated(self):
        state = _AgentState("example.com", set(), {"js_secrets", "smart_fuzz", "exposed", "admin", "subdomains"})
        self.assertFalse(state._already_covered("example.com", "verify_secrets"))
        self.assertFalse(state._already_covered("example.com", "run_module"))


if __name__ == "__main__":
    unittest.main()

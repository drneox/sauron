import os
import unittest
from unittest import mock

from modules import breach_check as bc


class QueryLeakcheckTests(unittest.TestCase):
    def test_rejects_junk_terms(self):
        for bad in ("", "a" * 400, "no spaces allowed here", "semi;colon"):
            self.assertEqual(bc.query_leakcheck(bad)["status"], "error")

    def test_accepts_email_and_bare_username(self):
        with mock.patch.dict(os.environ, {"LEAKCHECK_API_KEY": ""}):
            self.assertEqual(bc.query_leakcheck("user@example.com")["status"], "not_configured")
            self.assertEqual(bc.query_leakcheck("some.user-01")["status"], "not_configured")

    def test_not_configured_without_a_key(self):
        with mock.patch.dict(os.environ, {"LEAKCHECK_API_KEY": ""}):
            self.assertEqual(bc.query_leakcheck("user@example.com"), {"status": "not_configured"})

    def _mock_response(self, status_code, payload):
        resp = mock.Mock()
        resp.status_code = status_code
        resp.json.return_value = payload
        return resp

    def test_successful_lookup_returns_records_untouched(self):
        payload = {"success": True, "found": 1, "result": [{"email": "user@example.com", "source": {"name": "X"}}]}
        with mock.patch.dict(os.environ, {"LEAKCHECK_API_KEY": "k"}), \
             mock.patch.object(bc.httpx, "get", return_value=self._mock_response(200, payload)):
            out = bc.query_leakcheck("user@example.com")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["found"], 1)
        self.assertEqual(out["records"], payload["result"])

    def test_provider_error_is_surfaced_not_raised(self):
        payload = {"success": False, "error": "Invalid X-API-Key"}
        with mock.patch.dict(os.environ, {"LEAKCHECK_API_KEY": "bad"}), \
             mock.patch.object(bc.httpx, "get", return_value=self._mock_response(400, payload)):
            out = bc.query_leakcheck("user@example.com")
        self.assertEqual(out, {"status": "error", "error": "Invalid X-API-Key"})

    def test_rate_limited(self):
        with mock.patch.dict(os.environ, {"LEAKCHECK_API_KEY": "k"}), \
             mock.patch.object(bc.httpx, "get", return_value=self._mock_response(429, {"success": False})):
            out = bc.query_leakcheck("user@example.com")
        self.assertEqual(out["error"], "rate_limited")

    def test_network_failure_does_not_raise(self):
        with mock.patch.dict(os.environ, {"LEAKCHECK_API_KEY": "k"}), \
             mock.patch.object(bc.httpx, "get", side_effect=ConnectionError("boom")):
            out = bc.query_leakcheck("user@example.com")
        self.assertEqual(out, {"status": "error", "error": "request_failed"})


if __name__ == "__main__":
    unittest.main()

import base64
import json
import unittest

from modules.secret_verification import _analyze_jwt


def _jwt(header: dict, payload: dict) -> str:
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.sig"


class AnalyzeJwtTests(unittest.TestCase):
    def test_carries_the_source_the_frontend_needs_to_link_back_to_the_file(self):
        # Regression: the frontend used to read a "source" field this function
        # never returned, crashing (Cannot read properties of undefined
        # (reading 'split')) on any report with a JWT finding.
        out = _analyze_jwt(_jwt({"alg": "HS256"}, {}), source="https://example.com/app.js")
        self.assertEqual(out["source"], "https://example.com/app.js")

    def test_source_defaults_to_none_when_not_given(self):
        self.assertIsNone(_analyze_jwt(_jwt({"alg": "HS256"}, {}))["source"])

    def test_flags_none_algorithm_and_missing_expiration(self):
        out = _analyze_jwt(_jwt({"alg": "none"}, {}))
        self.assertIn("alg 'none' — token is unsigned", out["issues"])
        self.assertIn("no expiration (exp) claim", out["issues"])

    def test_reads_issuer_tenant_and_expiration(self):
        out = _analyze_jwt(_jwt({"alg": "RS256"}, {"iss": "https://issuer.example", "tid": "abc", "exp": 9999999999}))
        self.assertEqual(out["iss"], "https://issuer.example")
        self.assertEqual(out["tenant"], "abc")
        self.assertEqual(out["exp"], 9999999999)
        self.assertEqual(out["issues"], [])

    def test_malformed_token_is_flagged_without_raising(self):
        out = _analyze_jwt("not-a-jwt")
        self.assertIn("malformed JWT", out["issues"])


if __name__ == "__main__":
    unittest.main()

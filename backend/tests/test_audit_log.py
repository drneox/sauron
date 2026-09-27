import asyncio
import unittest

from modules import audit_log


class RedactTermTests(unittest.TestCase):
    def test_is_a_one_way_fingerprint(self):
        out = audit_log.redact_term("User@Example.com")
        self.assertEqual(len(out), 12)
        self.assertNotIn("user", out.lower())
        self.assertNotIn("example", out.lower())

    def test_same_term_same_hash_regardless_of_case_and_padding(self):
        self.assertEqual(audit_log.redact_term("user@example.com"),
                         audit_log.redact_term("  User@Example.COM "))

    def test_different_terms_differ(self):
        self.assertNotEqual(audit_log.redact_term("a@example.com"),
                            audit_log.redact_term("b@example.com"))


class CleanDetailTests(unittest.TestCase):
    def test_none_and_empty_yield_none(self):
        self.assertIsNone(audit_log._clean_detail(None))
        self.assertIsNone(audit_log._clean_detail({}))

    def test_long_strings_are_truncated(self):
        out = audit_log._clean_detail({"text": "x" * 600})
        self.assertEqual(len(out["text"]), audit_log.MAX_DETAIL_VALUE + 1)

    def test_keys_are_capped(self):
        out = audit_log._clean_detail({f"k{i}": i for i in range(50)})
        self.assertEqual(len(out), audit_log.MAX_DETAIL_KEYS)


class RecordTests(unittest.TestCase):
    def test_never_raises_even_without_a_db(self):
        # No Tortoise init here — AuditEvent.create will blow up, and record()
        # must swallow it (auditing must never break the audited action).
        asyncio.run(audit_log.record("auth.login", None, detail={"k": "v"}))

    def test_accepts_a_dev_user_dict(self):
        asyncio.run(audit_log.record("scan.start", {"id": 0, "email": "local@dev"}))


if __name__ == "__main__":
    unittest.main()

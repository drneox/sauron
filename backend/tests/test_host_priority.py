import unittest

from host_priority import host_priority


class HostPriorityTests(unittest.TestCase):
    def test_non_prod_environment_outranks_plain_host(self):
        self.assertGreater(
            host_priority("app.cert.example.com", "example.com"),
            host_priority("www.example.com", "example.com"),
        )

    def test_apex_suffix_is_not_read_as_a_name(self):
        # "dev" in the apex must not make every host look like a dev host.
        self.assertEqual(host_priority("www.dev-corp.com", "dev-corp.com"), 0)

    def test_tokens_are_whole_labels_not_substrings(self):
        self.assertEqual(host_priority("prepaid.example.com", "example.com"), 0)
        self.assertGreater(host_priority("app2-qa.example.com", "example.com"), 0)

    def test_evaluation_evidence_raises_priority(self):
        base = host_priority("shop.example.com", "example.com")
        alive = host_priority("shop.example.com", "example.com", None, {"alive": True, "risk": "low"})
        risky = host_priority("shop.example.com", "example.com", None, {"alive": True, "risk": "high"})
        self.assertGreater(alive, base)
        self.assertGreater(risky, alive)

    def test_source_sensitive_flag_counts(self):
        self.assertGreater(
            host_priority("shop.example.com", "example.com", {"sensitive": True}),
            host_priority("shop.example.com", "example.com", {}),
        )


if __name__ == "__main__":
    unittest.main()

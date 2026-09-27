import unittest

from main import _finding_host


class FindingHostTests(unittest.TestCase):
    def test_regular_module_uses_the_scan_target(self):
        # smart_fuzz (and every other deterministic-tier module) always runs
        # against the scan's own target, whatever that target is (an apex
        # domain in a full scan, or a subdomain in a fanned-out host scan).
        self.assertEqual(
            _finding_host("smart_fuzz", "[CRITICAL] Path discovered: /wp-config.php.old (HTTP 200, 3689 bytes)",
                          "carreras.example.com"),
            "carreras.example.com",
        )

    def test_subdomain_eval_reads_its_own_bracketed_host(self):
        # subdomain_eval evaluates hosts OTHER than the scan's own target, and
        # prefixes each line with the host it actually ran against.
        self.assertEqual(
            _finding_host("subdomain_eval", "[carreras.example.com] Missing security headers: ...", "example.com"),
            "carreras.example.com",
        )

    def test_subdomain_eval_non_host_lines_have_no_host(self):
        self.assertIsNone(_finding_host("subdomain_eval", "[secret verification] a leaked key was verified", "example.com"))
        self.assertIsNone(_finding_host("subdomain_eval", "New subdomain carreras.example.com evaluated as HIGH risk", "example.com"))

    def test_no_scan_target_yields_no_host(self):
        self.assertIsNone(_finding_host("headers", "Missing Strict-Transport-Security header", None))


if __name__ == "__main__":
    unittest.main()

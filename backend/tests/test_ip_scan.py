import unittest

import main
from pydantic import ValidationError


class NormalizeTargetTests(unittest.TestCase):
    def test_public_ipv4_passes(self):
        self.assertEqual(main._normalize_host_target("8.8.4.4"), "8.8.4.4")
        self.assertEqual(main._normalize_host_target(" https://8.8.8.8/x "), "8.8.8.8")

    def test_non_public_or_v6_is_refused(self):
        for bad in ("10.0.0.5", "127.0.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "2001:4860:4860::8888"):
            with self.assertRaises(ValueError, msg=bad):
                main._normalize_host_target(bad)

    def test_hostnames_still_validated(self):
        self.assertEqual(main._normalize_host_target("Api.Example.com"), "api.example.com")
        with self.assertRaises(ValueError):
            main._normalize_host_target("not a host")

    def test_request_model_accepts_ip_and_rejects_private(self):
        self.assertEqual(main.HostScanRequest(host="8.8.4.4").host, "8.8.4.4")
        with self.assertRaises(ValidationError):
            main.HostScanRequest(host="10.1.2.3")


class IpModuleSubsetTests(unittest.TestCase):
    def test_subset_only_has_address_level_modules(self):
        self.assertEqual(main.IP_SCAN_MODULES, {"ports", "blacklist"})
        self.assertTrue(main.IP_SCAN_MODULES <= main.HOST_SCAN_MODULES)

    def test_ip_scan_does_not_create_a_subdomain_asset(self):
        dom = type("D", (), {"domain": "example.com", "app_rejections": None})()
        result = {"kind": "host", "domain": "8.8.4.4", "modules": {
            "ports": {"ip": "8.8.4.4", "open_ports": [{"port": 443, "service": "HTTPS"}]}}}
        wanted = main._extract_asset_candidates(dom, result)
        self.assertNotIn(("subdomain", "8.8.4.4"), wanted)
        self.assertIn(("port", "8.8.4.4:443"), wanted)
        self.assertTrue(wanted[("ip", "8.8.4.4")]["ports_scanned"])


if __name__ == "__main__":
    unittest.main()

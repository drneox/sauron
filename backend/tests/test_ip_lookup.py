import unittest

from modules import ip_lookup as ipl


class ParsingTests(unittest.TestCase):
    def test_cymru_origin_and_name(self):
        info = ipl.parse_cymru_origin('"64512 | 203.0.113.0/24 | US | arin | 2015-11-24"')
        self.assertEqual((info["asn"], info["prefix"], info["country"]), ("64512", "203.0.113.0/24", "US"))
        self.assertEqual(
            ipl.parse_cymru_asn_name('"64512 | US | arin | 1997-03-31 | EXAMPLE-CORP-BLOCK - Example Corp, US"'),
            "EXAMPLE-CORP-BLOCK - Example Corp, US",
        )

    def test_multi_asn_origin_uses_the_first(self):
        self.assertEqual(ipl.parse_cymru_origin('"13335 15169 | 1.1.1.0/24 | AU | apnic | 2011-08-11"')["asn"], "13335")

    def test_garbage_is_none(self):
        self.assertIsNone(ipl.parse_cymru_origin("nonsense"))

    def test_only_public_ips_are_accepted(self):
        self.assertTrue(ipl.is_public_ip("8.8.8.8"))
        for bad in ("10.0.0.1", "127.0.0.1", "192.168.1.5", "169.254.169.254", "not-an-ip", ""):
            self.assertFalse(ipl.is_public_ip(bad), bad)

    def test_platform_headers_case_insensitive(self):
        self.assertEqual(ipl.platform_signals({"X-Azure-Ref": "1", "Server": "x"}), ["Azure Front Door / Azure CDN"])
        self.assertEqual(ipl.platform_signals({"Server": "nginx"}), [])


class VerdictTests(unittest.TestCase):
    def test_edge_with_web_ports_only_is_not_a_relation(self):
        probe = {"reachable": True, "platform_headers": ["Azure Front Door / Azure CDN"]}
        hint = ipl.verdict_hint({}, probe, [80, 443], 4)
        self.assertIn("not evidence of a relation", hint)

    def test_admin_ports_without_edge_headers_suggest_a_single_server(self):
        hint = ipl.verdict_hint({}, {"reachable": True, "platform_headers": []}, [22, 443], 2)
        self.assertIn("single server", hint)

    def test_unreachable_says_not_enough_signals(self):
        self.assertIn("Not enough signals", ipl.verdict_hint({}, {"reachable": False}, [], 1))


if __name__ == "__main__":
    unittest.main()

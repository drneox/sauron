import unittest

from modules import port_scan


class PortSeverityTests(unittest.TestCase):
    def test_scale_matches_how_the_module_reports_them(self):
        self.assertEqual(port_scan.port_severity(23), "critical")     # Telnet
        self.assertEqual(port_scan.port_severity(2375), "critical")   # Docker API
        self.assertEqual(port_scan.port_severity(22), "medium")       # SSH
        self.assertEqual(port_scan.port_severity(3389), "high")       # RDP
        self.assertEqual(port_scan.port_severity(6379), "high")       # Redis

    def test_web_and_unknown_ports_have_none(self):
        for p in (80, 443, 8081, 12345):
            self.assertIsNone(port_scan.port_severity(p))

    def test_every_severity_port_is_flagged_for_the_ui(self):
        for p in port_scan.CRITICAL_PORTS | port_scan.MEDIUM_PORTS | port_scan.RISKY_PORTS:
            self.assertIn(p, port_scan.FLAGGED_PORTS)


if __name__ == "__main__":
    unittest.main()

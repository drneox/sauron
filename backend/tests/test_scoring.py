# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the scoring model. Run from backend/:

    python -m unittest discover -s tests -t .
"""
import unittest

import scoring
from scoring import finding_category, grade_of_score, overall_score


class GradeThresholds(unittest.TestCase):
    def test_boundaries(self):
        cases = {100: "A", 90: "A", 89: "B", 75: "B", 74: "C", 60: "C", 59: "D", 40: "D", 39: "F", 0: "F"}
        for score, letter in cases.items():
            self.assertEqual(grade_of_score(score), letter, score)


class FindingCategories(unittest.TestCase):
    def test_email_only_spf_and_dmarc_are_defects(self):
        self.assertEqual(finding_category("email", "No SPF record found — email spoofing possible"), "misconfiguration")
        self.assertEqual(finding_category("email", "No DMARC record found — email authentication not enforced"), "misconfiguration")
        self.assertEqual(finding_category("email", "Email hosted on Google Workspace"), "info")
        self.assertEqual(finding_category("email", "DKIM not detectable via 30 common selectors"), "info")
        self.assertEqual(finding_category("email", "DMARC lookup inconclusive (DNS error) — record could not be verified"), "info")

    def test_blacklist_refusal_is_not_a_listing(self):
        self.assertEqual(finding_category("blacklist", "Blocklist check inconclusive: 5 list(s) refused the query"), "info")
        self.assertEqual(finding_category("blacklist", "IP 1.2.3.4 listed on Spamhaus ZEN"), "vulnerability")

    def test_subdomain_eval_and_headers_noise(self):
        self.assertEqual(finding_category("subdomain_eval", "Chained evaluation: 9/10 new subdomain(s) alive and evaluated"), "info")
        self.assertEqual(finding_category("subdomain_eval", "[a.x.com] Header 'Server: cloudflare' reveals server technology"), "info")
        self.assertEqual(finding_category("subdomain_eval", "[a.x.com] Header 'Server: nginx/1.14.1' reveals server technology"), "misconfiguration")
        self.assertEqual(finding_category("headers", "Header 'Server: awselb/2.0' reveals server technology"), "info")
        self.assertEqual(finding_category("headers", "Missing critical header: Content-Security-Policy"), "misconfiguration")

    def test_unknown_module_never_penalizes(self):
        self.assertEqual(finding_category("brand_new_module", "anything"), "info")

    def test_explicit_category_on_a_finding_wins(self):
        self.assertEqual(finding_category("whois", {"finding": "x", "category": "vulnerability"}), "vulnerability")


class FindingRisk(unittest.TestCase):
    def test_info_findings_carry_info_not_the_module_risk(self):
        self.assertEqual(scoring.finding_risk("high", "info"), "info")
        self.assertEqual(scoring.finding_risk("high", "misconfiguration"), "high")
        self.assertEqual(scoring.finding_risk("low", "vulnerability"), "low")

    def test_valid_finding_risks_include_info(self):
        self.assertEqual(set(scoring.FINDING_RISK_LEVELS), {"info", "low", "medium", "high", "critical"})


class OverallScore(unittest.TestCase):
    def test_clean_inventory_is_100_a(self):
        r = overall_score({"whois": {"risk": "low", "findings": ["Registrar: X"]}})
        self.assertEqual((r["score"], r["grade"], r["grade_capped_by"]), (100, "A", None))

    def test_severity_counts_modules_not_lines(self):
        lines = [f"Missing security header: X{i}" for i in range(45)]
        r = overall_score({"headers": {"risk": "medium", "findings": lines}})
        self.assertEqual(r["findings_by_severity"]["medium"], 1)

    def test_critical_caps_the_letter_but_not_the_score(self):
        res = {"blacklist": {"risk": "critical", "findings": ["IP 1.2.3.4 listed on SBL"]},
               "email": {"risk": "critical", "findings": ["No SPF record found — email spoofing possible"]}}
        r = overall_score(res)
        self.assertEqual(r["grade"], "D")
        self.assertGreater(r["score"], 59)                       # the number is the real one
        self.assertEqual(r["grade_capped_by"]["modules"], 2)
        self.assertEqual(r["grade_capped_by"]["cap"], "D")

    def test_cap_never_improves_a_worse_letter(self):
        bad = {m: {"risk": "critical", "findings": [f"No SPF record found {i}" for i in range(6)]}
               for m in ("email", "headers", "tls", "ssl", "cors", "cookies", "exposed", "blacklist",
                         "js_secrets", "frontend_cve", "waf", "dns")}
        r = overall_score(bad)
        self.assertIn(r["grade"], ("D", "F"))
        order = scoring.GRADE_ORDER
        self.assertGreaterEqual(order.index(r["grade"]), order.index(grade_of_score(r["score"])))

    def test_info_findings_never_change_the_result(self):
        base = overall_score({"email": {"risk": "high", "findings": ["No DMARC record found — email authentication not enforced"]}})
        noisy = overall_score({"email": {"risk": "high", "findings": [
            "No DMARC record found — email authentication not enforced",
            "Email hosted on Google Workspace", "DKIM not detectable via 30 common selectors"]}})
        self.assertEqual((base["score"], base["grade"]), (noisy["score"], noisy["grade"]))


    def test_missing_waf_is_a_medium_exposure_that_caps_the_letter_at_b(self):
        clean = overall_score({})
        no_waf = overall_score({"waf": {"risk": "medium",
                                        "findings": ["No WAF or CDN detected — origin server may be directly exposed"]}})
        self.assertEqual(scoring.finding_category("waf", "No WAF or CDN detected — origin server may be directly exposed"), "exposure")
        self.assertEqual(clean["grade"], "A")
        self.assertEqual(no_waf["grade"], "B")
        self.assertEqual(no_waf["grade_capped_by"]["severity"], "medium")
        self.assertGreaterEqual(no_waf["score"], 90)     # the number barely moves

    def test_detected_waf_is_only_a_note(self):
        r = overall_score({"waf": {"risk": "low", "findings": ["WAF detected: Cloudflare (confidence 90%)"]}})
        self.assertEqual((r["score"], r["grade"]), (100, "A"))
        self.assertEqual(scoring.finding_category("waf", "WAF detected: Cloudflare (confidence 90%)"), "info")


if __name__ == "__main__":
    unittest.main()

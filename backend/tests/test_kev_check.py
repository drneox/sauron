import unittest
from unittest import mock

from modules import kev_check as kev

WP_CORE = {"cveID": "CVE-2020-0001", "vendorProject": "WordPress", "product": "Core",
           "vulnerabilityName": "WordPress Core RCE", "dateAdded": "2024-01-01",
           "knownRansomwareCampaignUse": "Unknown", "requiredAction": "Update", "dueDate": "2024-02-01"}
PLUGIN = {"cveID": "CVE-2020-0002", "vendorProject": "WordPress", "product": "File Manager Plugin",
          "vulnerabilityName": "File Manager RCE", "dateAdded": "2024-01-01",
          "knownRansomwareCampaignUse": "Known", "requiredAction": "Update", "dueDate": "2024-02-01"}
CATALOG = [WP_CORE, PLUGIN,
           {"cveID": "CVE-2020-0003", "vendorProject": "Apache", "product": "Tomcat"}]


def rng(product, start_incl=None, end_excl=None, version="*"):
    return {"product": product, "version": version, "start_incl": start_incl, "start_excl": None,
            "end_incl": None, "end_excl": end_excl}


class CandidateTests(unittest.TestCase):
    def test_core_product_matches_vendor_and_product(self):
        hits, cpe = kev.kev_candidates("WordPress", CATALOG)
        self.assertEqual([h["cveID"] for h in hits], ["CVE-2020-0001"])
        self.assertIn("wordpress", cpe)

    def test_plugin_slug_matches_kev_product_words(self):
        hits, cpe = kev.kev_candidates("wp-file-manager (WP plugin)", CATALOG)
        self.assertEqual([h["cveID"] for h in hits], ["CVE-2020-0002"])
        self.assertEqual(cpe, {"wpfilemanager"})

    def test_unrelated_slug_does_not_match(self):
        self.assertEqual(kev.kev_candidates("elementor (WP plugin)", CATALOG)[0], [])

    def test_unknown_technology_has_no_candidates(self):
        self.assertEqual(kev.kev_candidates("React", CATALOG)[0], [])


class RangeTests(unittest.TestCase):
    def test_version_inside_and_outside_range(self):
        ranges = [rng("wordpress", start_incl="5.0", end_excl="5.8.3")]
        v = kev.parse_version
        self.assertIsNotNone(kev.version_affected(v("5.7.1"), ranges, {"wordpress"}))
        self.assertIsNone(kev.version_affected(v("5.8.3"), ranges, {"wordpress"}))
        self.assertIsNone(kev.version_affected(v("4.9"), ranges, {"wordpress"}))

    def test_other_products_ranges_are_ignored(self):
        ranges = [rng("wordpress", end_excl="99.0")]
        self.assertIsNone(kev.version_affected(kev.parse_version("1.0"), ranges, {"tomcat"}))

    def test_exact_version_row(self):
        ranges = [rng("php", version="7.4.3")]
        self.assertIsNotNone(kev.version_affected(kev.parse_version("7.4.3"), ranges, {"php"}))
        self.assertIsNone(kev.version_affected(kev.parse_version("7.4.4"), ranges, {"php"}))

    def test_unbounded_wildcard_proves_nothing(self):
        self.assertIsNone(kev.version_affected(kev.parse_version("1.0"), [rng("php")], {"php"}))

    def test_parse_version_reads_leading_numbers(self):
        self.assertEqual(str(kev.parse_version("7.4.3-1ubuntu2")), "7.4.3")
        self.assertIsNone(kev.parse_version("unknown"))

    def test_extract_ranges_keeps_only_vulnerable_matches(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", "versionEndExcluding": "5.8.3"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
        ]}]}]}
        out = kev.extract_ranges(cve)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["product"], out[0]["end_excl"]), ("wordpress", "5.8.3"))


class RunTests(unittest.TestCase):
    def _run(self, tech, ranges_by_cve):
        with mock.patch.object(kev.tech_fingerprint, "run", return_value=tech), \
             mock.patch.object(kev, "_load_kev", return_value=CATALOG), \
             mock.patch.object(kev, "_nvd_ranges", side_effect=lambda cve, _d: ranges_by_cve.get(cve)):
            return kev.run("example.com")

    def test_affected_version_yields_finding_and_ransomware_is_critical(self):
        out = self._run(
            {"status": "ok", "technologies": ["wp-file-manager (WP plugin)"],
             "versions": {"wp-file-manager (WP plugin)": "6.0"}},
            {"CVE-2020-0002": [rng("wpfilemanager", end_excl="6.9")]},
        )
        self.assertEqual(out["risk"], "critical")
        self.assertEqual(out["matches"][0]["cve"], "CVE-2020-0002")
        self.assertIn("[KEV]", out["findings"][0])

    def test_patched_version_yields_nothing(self):
        out = self._run(
            {"status": "ok", "technologies": ["WordPress"], "versions": {"WordPress": "6.5"}},
            {"CVE-2020-0001": [rng("wordpress", end_excl="5.8.3")]},
        )
        self.assertEqual((out["findings"], out["risk"]), ([], "low"))

    def test_no_version_is_unverifiable_not_a_finding(self):
        out = self._run({"status": "ok", "technologies": ["WordPress"], "versions": {}}, {})
        self.assertEqual(out["findings"], [])
        self.assertEqual(out["unverifiable"][0]["technology"], "WordPress")

    def test_nvd_unavailable_is_unverified_not_a_finding(self):
        out = self._run({"status": "ok", "technologies": ["WordPress"], "versions": {"WordPress": "5.0"}}, {})
        self.assertEqual(out["findings"], [])
        self.assertEqual(out["unverified"], ["CVE-2020-0001"])


if __name__ == "__main__":
    unittest.main()

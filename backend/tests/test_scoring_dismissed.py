import unittest

from scoring import finding_risk, line_risk, overall_score


def module(risk, *lines):
    return {"risk": risk, "findings": list(lines)}


class LineRiskTests(unittest.TestCase):
    def test_tag_lowers_but_never_raises(self):
        self.assertEqual(line_risk("critical", "[MEDIUM] Path discovered: /wp-json/"), "medium")
        self.assertEqual(line_risk("critical", "[CRITICAL] Path discovered: /.env"), "critical")
        self.assertEqual(line_risk("medium", "[HIGH] something"), "medium")      # module is the ceiling

    def test_untagged_or_odd_lines_inherit(self):
        self.assertEqual(line_risk("high", "Missing critical header: Content-Security-Policy"), "high")
        self.assertEqual(line_risk("high", {"finding": "[LOW] x"}), "low")
        self.assertEqual(line_risk("high", {"not": "text"}), "high")

    def test_info_findings_stay_info(self):
        self.assertEqual(finding_risk("high", "info", "[HIGH] x"), "info")
        self.assertEqual(finding_risk("high", "exposure", "[MEDIUM] x"), "medium")
        self.assertEqual(finding_risk("high", "exposure"), "high")


class DismissedScoreTests(unittest.TestCase):
    def results(self):
        return {"smart_fuzz": module(
            "critical",
            "[CRITICAL] Path discovered: /wp-config.php.old (HTTP 200, 3689 bytes)",
            "[MEDIUM] Path discovered: /wp-json/ (HTTP 200, 406975 bytes)",
            "[MEDIUM] Path discovered: /wp-json/wp/v2/types (HTTP 200, 9055 bytes)",
        )}

    def test_dismissing_everything_scored_drops_the_module(self):
        full = overall_score(self.results())
        none_left = overall_score(self.results(), {"smart_fuzz": {0, 1, 2}})
        self.assertGreater(none_left["score"], full["score"])
        self.assertEqual(none_left["findings_by_severity"]["critical"], 0)
        self.assertEqual(none_left["overall_risk"], "low")

    def test_dismissing_the_critical_line_lowers_the_module_to_what_remains(self):
        sc = overall_score(self.results(), {"smart_fuzz": {0}})
        self.assertEqual(sc["findings_by_severity"]["critical"], 0)
        self.assertEqual(sc["findings_by_severity"]["medium"], 1)
        self.assertEqual(sc["overall_risk"], "medium")

    def test_dismissing_noise_keeps_the_real_critical(self):
        base = overall_score(self.results())
        sc = overall_score(self.results(), {"smart_fuzz": {1, 2}})
        self.assertEqual(sc["findings_by_severity"]["critical"], 1)
        self.assertGreaterEqual(sc["score"], base["score"])
        self.assertIn(sc["grade"], "DF")                    # a critical still caps the letter

    def test_nothing_dismissed_is_the_plain_score(self):
        self.assertEqual(overall_score(self.results(), {}), overall_score(self.results()))

    def test_untagged_remaining_lines_keep_the_module_risk(self):
        res = {"headers": module("high", "Missing critical header: Strict-Transport-Security",
                                 "Missing critical header: Content-Security-Policy")}
        sc = overall_score(res, {"headers": {0}})
        self.assertEqual(sc["findings_by_severity"]["high"], 1)


if __name__ == "__main__":
    unittest.main()

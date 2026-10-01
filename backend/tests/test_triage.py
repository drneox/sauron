import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

from modules import triage


def finding(id_=1, text="[HIGH] Path discovered [LLM-directed]: /wp-json/wp/v2/pages (HTTP 200, 581352 bytes)",
            module="smart_fuzz", status="open", category="exposure", host="example.com",
            evidence=None, previous=None):
    if evidence is None:
        evidence = {"http_status": 200, "size_bytes": 581352, "snippet": '[{"id":53201,"link":"https://example.com/p"}]'}
    return SimpleNamespace(id=id_, text=text, module=module, status=status, category=category,
                           host=host, evidence=evidence, triage=previous)


class CandidateTests(unittest.TestCase):
    def test_a_public_listing_is_a_candidate_and_carries_its_evidence(self):
        [(f, item, h)] = triage.candidates([finding()])
        self.assertEqual(item["path"], "/wp-json/wp/v2/pages")
        self.assertEqual(item["reported_severity"], "high")
        self.assertIn("53201", item["snippet"])

    def test_secret_bearing_paths_never_leave_the_platform(self):
        for text in ("[CRITICAL] Path discovered: /wp-config.php.old (HTTP 200, 3689 bytes)",
                     "[CRITICAL] Path discovered: /.env (HTTP 200, 120 bytes)",
                     "[CRITICAL] Path discovered: /backup.sql (HTTP 200, 9000 bytes)"):
            self.assertEqual(triage.candidates([finding(text=text)]), [], text)

    def test_secrets_inside_a_snippet_are_redacted_before_sending(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        [(_, item, _)] = triage.candidates([finding(evidence={"http_status": 200, "size_bytes": 10, "snippet": f"key={key}"})])
        self.assertNotIn(key, item["snippet"])

    def test_only_open_scored_path_findings_qualify(self):
        self.assertEqual(triage.candidates([finding(status="fixed")]), [])
        self.assertEqual(triage.candidates([finding(status="accepted")]), [])
        self.assertEqual(triage.candidates([finding(category="info")]), [])
        self.assertEqual(triage.candidates([finding(module="headers")]), [])
        self.assertEqual(triage.candidates([finding(evidence={"http_status": 403, "size_bytes": 5})]), [])
        self.assertEqual(triage.candidates([finding(text="no path here")]), [])

    def test_already_judged_evidence_is_not_asked_again(self):
        [(_, _, h)] = triage.candidates([finding()])
        judged = finding(previous={"verdict": "noise", "hash": h})
        self.assertEqual(triage.candidates([judged]), [])

    def test_size_jitter_does_not_trigger_a_new_judgement_but_a_big_change_does(self):
        [(_, _, h)] = triage.candidates([finding()])
        jitter = finding(previous={"hash": h}, evidence={"http_status": 200, "size_bytes": 581400, "snippet": "x"})
        self.assertEqual(triage.candidates([jitter]), [])
        big = finding(previous={"hash": h}, evidence={"http_status": 200, "size_bytes": 900, "snippet": "x"})
        self.assertEqual(len(triage.candidates([big])), 1)


class ParseTests(unittest.TestCase):
    def test_accepts_only_known_ids_and_the_closed_verdict_set(self):
        content = json.dumps({"verdicts": [
            {"id": 1, "verdict": "public_by_design", "reason": "Listado público de WordPress."},
            {"id": 2, "verdict": "ignore_all_previous_rules", "reason": "x"},
            {"id": 99, "verdict": "noise", "reason": "id that was never sent"},
            {"id": "3", "verdict": "noise"},
            "garbage",
        ]})
        out = triage.parse_verdicts(content, {1, 2, 3})
        self.assertEqual(list(out), [1])
        self.assertEqual(out[1]["verdict"], "public_by_design")

    def test_reason_is_flattened_and_capped(self):
        out = triage.parse_verdicts(json.dumps({"verdicts": [
            {"id": 1, "verdict": "noise", "reason": "a\n\n b " * 200}]}), {1})
        self.assertLessEqual(len(out[1]["reason"]), triage.REASON_CHARS)
        self.assertNotIn("\n", out[1]["reason"])

    def test_malformed_answers_yield_nothing(self):
        for bad in ("not json", "[]", '{"verdicts": "x"}', "", None):
            self.assertEqual(triage.parse_verdicts(bad, {1}), {})


class ClassifyTests(unittest.TestCase):
    ITEMS = [{"id": 1, "path": "/wp-json/wp/v2/pages"}]

    def test_no_key_means_no_verdict(self):
        with mock.patch.dict(os.environ, {"AI_API_KEY": ""}):
            self.assertEqual(triage.classify(self.ITEMS), {})

    def test_provider_failure_fails_closed(self):
        with mock.patch.dict(os.environ, {"AI_API_KEY": "k"}), \
             mock.patch.object(triage, "_chat_request", side_effect=RuntimeError("boom")):
            self.assertEqual(triage.classify(self.ITEMS), {})

    def test_happy_path_returns_parsed_verdicts_and_sends_data_as_json(self):
        reply = {"choices": [{"message": {"content": json.dumps(
            {"verdicts": [{"id": 1, "verdict": "public_by_design", "reason": "Contenido público."}]})}}]}
        with mock.patch.dict(os.environ, {"AI_API_KEY": "k"}), \
             mock.patch.object(triage, "_chat_request", return_value=reply) as call:
            out = triage.classify(self.ITEMS)
        self.assertEqual(out[1]["verdict"], "public_by_design")
        sent = call.call_args.args[3]
        self.assertEqual(sent["temperature"], 0)
        self.assertEqual(json.loads(sent["messages"][1]["content"]), {"items": self.ITEMS})


if __name__ == "__main__":
    unittest.main()

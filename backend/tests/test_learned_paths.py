import asyncio
import unittest
from types import SimpleNamespace

from tortoise import Tortoise

import learned_paths as lp
from db import LearnedPath

KNOWN = {"/admin", "/.env"}


def run(coro_fn):
    async def runner():
        await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["db"]})
        await Tortoise.generate_schemas()
        try:
            return await coro_fn()
        finally:
            await Tortoise.close_connections()
    return asyncio.run(runner())


def scan(host, *hits):
    return {"domain": host, "modules": {"smart_fuzz": {"paths_found": list(hits)}}}


def hit(path, status=200, directed=True):
    return {"path": path, "status": status, "directed": directed}


class SafePathTests(unittest.TestCase):
    def test_plain_static_routes_are_safe(self):
        for p in ("/status", "/api/v1/health", "/actuator/info", "/.well-known/security.txt"):
            self.assertTrue(lp.is_safe_path(p), p)

    def test_unsafe_shapes_are_rejected(self):
        for p in ("/", "/logout", "/api/users/delete", "/a?x=1", "/../etc", "/a/b/c/d/e",
                  "/pay", "/cancel-order", "/with space", "/x" * 20, "/%2e%2e"):
            self.assertFalse(lp.is_safe_path(p), p)


class HitsFromResultTests(unittest.TestCase):
    def test_only_directed_2xx_unknown_safe_hits(self):
        result = scan(
            "a.example.com",
            hit("/status"),                       # kept
            hit("/health", directed=False),       # static wordlist hit, not learned
            hit("/maybe", status=403),            # not a success
            hit("/admin"),                        # already in a wordlist
            hit("/logout"),                       # unsafe
            hit("/Metrics/"),                     # normalized
            "junk",
        )
        self.assertEqual(lp.hits_from_result(result, KNOWN), [("/status", 200), ("/metrics", 200)])

    def test_missing_module_is_empty(self):
        self.assertEqual(lp.hits_from_result({"domain": "a"}, KNOWN), [])


class CandidateTests(unittest.TestCase):
    def row(self, **kw):
        base = dict(path="/status", status="seen", hosts=["a", "b"], ai_verdict=None)
        base.update(kw)
        return SimpleNamespace(**base)

    def test_needs_two_hosts(self):
        self.assertTrue(lp.is_candidate(self.row()))
        self.assertFalse(lp.is_candidate(self.row(hosts=["a"])))

    def test_ai_dismissed_or_decided_is_not_candidate(self):
        self.assertFalse(lp.is_candidate(self.row(ai_verdict="public_by_design")))
        self.assertFalse(lp.is_candidate(self.row(ai_verdict="noise")))
        self.assertTrue(lp.is_candidate(self.row(ai_verdict="confirmed")))
        self.assertFalse(lp.is_candidate(self.row(status="approved")))
        self.assertFalse(lp.is_candidate(self.row(status="rejected")))


class RecordHitsTests(unittest.TestCase):
    def test_hosts_accumulate_and_candidate_after_second_host(self):
        async def go():
            await lp.record_hits(scan("a.example.com", hit("/status")), KNOWN)
            await lp.record_hits(scan("a.example.com", hit("/status")), KNOWN)
            row = await LearnedPath.get(path="/status")
            self.assertEqual((row.hosts, row.hits, lp.is_candidate(row)), (["a.example.com"], 2, False))
            await lp.record_hits(scan("b.example.com", hit("/status")), KNOWN)
            row = await LearnedPath.get(path="/status")
            self.assertEqual(len(row.hosts), 2)
            self.assertTrue(lp.is_candidate(row))
        run(go)

    def test_nothing_recorded_without_host_or_hits(self):
        async def go():
            self.assertEqual(await lp.record_hits({"modules": {}}, KNOWN), 0)
            self.assertEqual(await lp.record_hits(scan("a.example.com", hit("/admin")), KNOWN), 0)
            self.assertEqual(await LearnedPath.all().count(), 0)
        run(go)

    def test_auto_approve_only_when_generic(self):
        async def go():
            await lp.record_hits(scan("a.example.com", hit("/status")), KNOWN, auto_approve=True)
            self.assertEqual(await lp.approved_paths(), [])
            await lp.record_hits(scan("b.example.com", hit("/status")), KNOWN, auto_approve=True)
            self.assertEqual(await lp.approved_paths(), ["/status"])
            row = await LearnedPath.get(path="/status")
            self.assertEqual(row.decided_by, "auto")
        run(go)

    def test_auto_approve_skips_ai_dismissed(self):
        async def go():
            await lp.record_hits(scan("a.example.com", hit("/status")), KNOWN)
            await lp.set_verdict("/status", "noise")
            await lp.record_hits(scan("b.example.com", hit("/status")), KNOWN, auto_approve=True)
            self.assertEqual(await lp.approved_paths(), [])
        run(go)


class ApprovedPathsTests(unittest.TestCase):
    def test_unsafe_or_unapproved_rows_never_load(self):
        async def go():
            await LearnedPath.create(path="/ok", status="approved", hosts=["a", "b"])
            await LearnedPath.create(path="/logout", status="approved", hosts=["a", "b"])  # hand-edited
            await LearnedPath.create(path="/seen", status="seen", hosts=["a", "b"])
            await LearnedPath.create(path="/nope", status="rejected", hosts=["a", "b"])
            self.assertEqual(await lp.approved_paths(), ["/ok"])
        run(go)

    def test_decide_records_who(self):
        async def go():
            row = await LearnedPath.create(path="/ok", hosts=["a", "b"])
            await lp.decide(row, "approved", "admin@example.com")
            row = await LearnedPath.get(id=row.id)
            self.assertEqual((row.status, row.decided_by), ("approved", "admin@example.com"))
            self.assertIsNotNone(row.decided_at)
        run(go)


if __name__ == "__main__":
    unittest.main()

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from tortoise import Tortoise

from db import Asset, AssetHistory, Company, Domain, Finding, Scan, Schedule
from domain_merge import MergeRefused, find_orphan_merges, merge_domain_into

T0 = datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)


def at(days: float) -> datetime:
    return T0 + timedelta(days=days)


def run(coro_fn):
    """Fresh in-memory SQLite per test: the same models, no external DB."""
    async def runner():
        await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["db"]})
        await Tortoise.generate_schemas()
        try:
            return await coro_fn()
        finally:
            await Tortoise.close_connections()
    return asyncio.run(runner())


async def _finding(domain, fp, status, seen_days, fixed_days=None, **kw):
    return await Finding.create(
        domain_id=domain.id, fingerprint=fp, module=kw.pop("module", "smart_fuzz"),
        text=kw.pop("text", fp), host=kw.pop("host", "app.example.com"),
        risk=kw.pop("risk", "high"), category="vulnerability", status=status,
        first_seen_scan_id="s0", last_seen_scan_id=kw.pop("scan", "s1"),
        first_seen_at=at(kw.pop("first_days", 0)), last_seen_at=at(seen_days),
        fixed_at=at(fixed_days) if fixed_days is not None else None, **kw)


async def _pair():
    company = await Company.create(name="acme")
    owned = await Domain.create(company_id=company.id, domain="example.com")
    orphan = await Domain.create(company_id=None, domain="example.com")
    return company, owned, orphan


class MergeFindingsTests(unittest.TestCase):
    def test_a_newer_open_sighting_reopens_a_closed_finding(self):
        # The real case: the company row says "fixed" (swept), the orphan holds
        # the later host scan that found the file again.
        async def go():
            _, owned, orphan = await _pair()
            await _finding(owned, "fp1", "fixed", seen_days=4, fixed_days=6)
            await _finding(orphan, "fp1", "open", seen_days=7, scan="s-new")
            stats = await merge_domain_into(orphan, owned)
            rows = await Finding.filter(domain_id=owned.id)
            return stats, rows
        stats, rows = run(go)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "open")
        self.assertIsNone(rows[0].fixed_at)
        self.assertEqual(rows[0].last_seen_scan_id, "s-new")
        self.assertEqual(stats["findings_reopened"], 1)

    def test_an_older_open_copy_does_not_reopen_a_later_fix(self):
        async def go():
            _, owned, orphan = await _pair()
            await _finding(owned, "fp1", "fixed", seen_days=4, fixed_days=9)
            await _finding(orphan, "fp1", "open", seen_days=5)
            await merge_domain_into(orphan, owned)
            return await Finding.get(domain_id=owned.id, fingerprint="fp1")
        row = run(go)
        self.assertEqual(row.status, "fixed")

    def test_accepted_is_an_operator_decision_and_survives(self):
        async def go():
            _, owned, orphan = await _pair()
            await _finding(owned, "fp1", "accepted", seen_days=1, notes="risk accepted by CISO")
            await _finding(orphan, "fp1", "open", seen_days=8)
            await merge_domain_into(orphan, owned)
            return await Finding.get(domain_id=owned.id, fingerprint="fp1")
        row = run(go)
        self.assertEqual(row.status, "accepted")
        self.assertEqual(row.notes, "risk accepted by CISO")

    def test_false_positive_is_an_operator_decision_and_survives(self):
        async def go():
            _, owned, orphan = await _pair()
            await _finding(owned, "fp1", "open", seen_days=8)
            await _finding(orphan, "fp1", "false_positive", seen_days=1, notes="IA: public by design")
            await merge_domain_into(orphan, owned)
            return await Finding.get(domain_id=owned.id, fingerprint="fp1")
        row = run(go)
        self.assertEqual(row.status, "false_positive")
        self.assertEqual(row.notes, "IA: public by design")

    def test_unique_findings_move_and_first_seen_keeps_the_earliest(self):
        async def go():
            _, owned, orphan = await _pair()
            await _finding(owned, "shared", "open", seen_days=5, first_days=3)
            await _finding(orphan, "shared", "open", seen_days=2, first_days=1)
            await _finding(orphan, "only-orphan", "open", seen_days=2)
            await merge_domain_into(orphan, owned)
            return {f.fingerprint: f for f in await Finding.filter(domain_id=owned.id)}
        rows = run(go)
        self.assertEqual(set(rows), {"shared", "only-orphan"})
        self.assertEqual(rows["shared"].first_seen_at, at(1))
        self.assertEqual(rows["shared"].last_seen_at, at(5))


class MergeInventoryTests(unittest.TestCase):
    def test_assets_merge_keeps_explicit_timestamps_and_history(self):
        async def go():
            _, owned, orphan = await _pair()
            a_owned = await Asset.create(domain_id=owned.id, type="subdomain", value="app.example.com",
                                         metadata={"v": "old"}, first_seen_scan_id="a", last_seen_scan_id="a")
            a_orph = await Asset.create(domain_id=orphan.id, type="subdomain", value="app.example.com",
                                        metadata={"v": "new"}, first_seen_scan_id="b", last_seen_scan_id="b")
            await Asset.create(domain_id=orphan.id, type="ip", value="1.2.3.4",
                               first_seen_scan_id="b", last_seen_scan_id="b")
            # force known timestamps (bypassing auto_now/auto_now_add)
            await Asset.filter(id=a_owned.id).update(first_seen_at=at(3), last_seen_at=at(4))
            await Asset.filter(id=a_orph.id).update(first_seen_at=at(1), last_seen_at=at(9))
            await AssetHistory.create(asset_id=a_orph.id, scan_id="b", old_metadata=None, new_metadata={"v": "new"})
            stats = await merge_domain_into(orphan, owned)
            twin = await Asset.get(domain_id=owned.id, type="subdomain", value="app.example.com")
            history = await AssetHistory.filter(asset_id=twin.id).count()
            return stats, twin, history, await Asset.filter(domain_id=owned.id).count()
        stats, twin, history, total = run(go)
        self.assertEqual(total, 2)
        self.assertEqual((stats["assets_moved"], stats["assets_merged"]), (1, 1))
        self.assertEqual(twin.first_seen_at, at(1))     # earliest first sighting
        self.assertEqual(twin.last_seen_at, at(9))      # not stamped "now"
        self.assertEqual(twin.metadata, {"v": "new"})   # the newer observation wins
        self.assertEqual(history, 1)

    def test_scans_move_and_the_source_row_is_gone(self):
        async def go():
            _, owned, orphan = await _pair()
            await Scan.create(id="scan-1", domain_id=orphan.id, kind="host", scan_target="app.example.com",
                              status="completed", started_at=at(1))
            await merge_domain_into(orphan, owned)
            return (await Scan.get(id="scan-1")).domain_id == owned.id, await Domain.filter(id=orphan.id).exists()
        moved, still_there = run(go)
        self.assertTrue(moved)
        self.assertFalse(still_there)

    def test_schedule_of_the_target_wins(self):
        async def go():
            _, owned, orphan = await _pair()
            await Schedule.create(domain_id=owned.id, interval_hours=24)
            await Schedule.create(domain_id=orphan.id, interval_hours=1)
            stats = await merge_domain_into(orphan, owned)
            return stats, [s.interval_hours for s in await Schedule.filter(domain_id=owned.id)]
        stats, intervals = run(go)
        self.assertEqual(intervals, [24])
        self.assertEqual(stats["schedule_dropped"], 1)

    def test_review_decisions_are_unioned(self):
        async def go():
            _, owned, orphan = await _pair()
            await Domain.filter(id=owned.id).update(app_rejections=[{"store": "app_store", "name": "A"}])
            await Domain.filter(id=orphan.id).update(app_rejections=[{"store": "app_store", "name": "A"},
                                                                    {"store": "google_play", "name": "B"}])
            await merge_domain_into(await Domain.get(id=orphan.id), await Domain.get(id=owned.id))
            return (await Domain.get(id=owned.id)).app_rejections
        rejections = run(go)
        self.assertEqual(sorted(r["name"] for r in rejections), ["A", "B"])


class SafetyTests(unittest.TestCase):
    def test_refuses_different_names_or_foreign_companies(self):
        async def go():
            c1 = await Company.create(name="one")
            c2 = await Company.create(name="two")
            a = await Domain.create(company_id=c1.id, domain="same.example")
            b = await Domain.create(company_id=c2.id, domain="same.example")
            other = await Domain.create(company_id=None, domain="other.example")
            errors = []
            for src, dst in ((a, b), (other, a), (a, a)):
                try:
                    await merge_domain_into(src, dst)
                except MergeRefused as e:
                    errors.append(str(e))
            return errors, await Domain.filter(id=a.id).exists()
        errors, a_survived = run(go)
        self.assertEqual(len(errors), 3)
        self.assertTrue(a_survived)

    def test_orphan_pairs_only_when_exactly_one_owner(self):
        async def go():
            c1 = await Company.create(name="one")
            c2 = await Company.create(name="two")
            o1 = await Domain.create(company_id=None, domain="solo.example")
            await Domain.create(company_id=c1.id, domain="solo.example")
            o2 = await Domain.create(company_id=None, domain="ambiguous.example")
            await Domain.create(company_id=c1.id, domain="ambiguous.example")
            await Domain.create(company_id=c2.id, domain="ambiguous.example")
            await Domain.create(company_id=None, domain="alone.example")
            return o1.id, [(o.id, d.company_id) for o, d in await find_orphan_merges()]
        o1_id, pairs = run(go)
        self.assertEqual(pairs, [(o1_id, pairs[0][1])])


if __name__ == "__main__":
    unittest.main()

"""Merging duplicate Domain rows.

Two rows for the same domain string split one host's history in two: scans,
inventory and — worst — findings, where a company view only ever reads the
rows filed under its own domain ids. The usual shape is an orphan row (a
quick scan with no company) next to the company-owned row for the same
string; `merge_domain_into` folds the orphan into the owned row without
losing anything and without letting a stale copy overwrite a newer one.

Conflict rules (rows that exist on both sides):
  - assets / subdomains / endpoints: the target row stays; the source's
    observation wins only when it is newer, first-seen keeps the earliest.
  - findings: first-seen keeps the earliest. An `accepted` status is an
    operator decision and survives either way; otherwise the side whose
    latest event is newer decides open vs fixed (an `open` sighting after a
    `fixed_at` reopens the finding — exactly what the false auto-closes of
    host findings need).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from tortoise.transactions import in_transaction

from db import Asset, AssetHistory, Domain, Endpoint, Finding, Scan, Schedule, Subdomain

logger = logging.getLogger(__name__)

EPOCH = datetime.min.replace(tzinfo=timezone.utc)


class MergeRefused(ValueError):
    """The two rows must not be merged (message says why)."""


def check_mergeable(source: Domain, target: Domain) -> None:
    if source.id == target.id:
        raise MergeRefused("source and target are the same domain row")
    if source.domain.strip().lower() != target.domain.strip().lower():
        raise MergeRefused("rows are for different domain names")
    # Folding one company's domain into another's would silently take the
    # domain away from a company; only an orphan (or a same-company row) may go.
    if source.company_id is not None and source.company_id != target.company_id:
        raise MergeRefused("source belongs to a different company than target")


def _aware(dt: datetime | None) -> datetime:
    if dt is None:
        return EPOCH
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _finding_event_time(f: Finding) -> datetime:
    """When this row last said something about the finding: the fix for a
    fixed one, the latest sighting otherwise."""
    if f.status == "fixed" and f.fixed_at:
        return _aware(f.fixed_at)
    return _aware(f.last_seen_at)


def reconcile_findings(keep: Finding, other: Finding) -> dict[str, Any]:
    """Field values for `keep` after absorbing `other` (same fingerprint)."""
    first, later_first = (keep, other) if _aware(keep.first_seen_at) <= _aware(other.first_seen_at) else (other, keep)
    newer_seen = keep if _aware(keep.last_seen_at) >= _aware(other.last_seen_at) else other
    values: dict[str, Any] = {
        "first_seen_at": first.first_seen_at,
        "first_seen_scan_id": first.first_seen_scan_id,
        "last_seen_at": newer_seen.last_seen_at,
        "last_seen_scan_id": newer_seen.last_seen_scan_id,
        # The newest sighting has the freshest classification and context.
        "risk": newer_seen.risk,
        "category": newer_seen.category,
        "frameworks": newer_seen.frameworks,
        "evidence": newer_seen.evidence if newer_seen.evidence is not None else keep.evidence or other.evidence,
        "host": newer_seen.host or keep.host or other.host,
        "triage": newer_seen.triage if newer_seen.triage is not None else keep.triage or other.triage,
    }
    if "accepted" in (keep.status, other.status):
        accepted = keep if keep.status == "accepted" else other
        values["status"] = "accepted"
        values["fixed_at"] = None
        values["notes"] = accepted.notes
    else:
        winner = keep if _finding_event_time(keep) >= _finding_event_time(other) else other
        values["status"] = winner.status
        values["fixed_at"] = winner.fixed_at if winner.status == "fixed" else None
        values["notes"] = keep.notes or other.notes
    if keep.notes and other.notes and keep.notes != other.notes and values["status"] != "accepted":
        values["notes"] = f"{keep.notes}\n{other.notes}"
    return values


def _union_by(items_a: list | None, items_b: list | None, keys: tuple[str, ...]) -> list | None:
    merged: dict[tuple, dict] = {}
    for item in list(items_a or []) + list(items_b or []):
        if isinstance(item, dict):
            merged.setdefault(tuple(item.get(k) for k in keys), item)
    return list(merged.values()) or None


async def merge_domain_into(source: Domain, target: Domain) -> dict[str, int]:
    """Fold `source` into `target` (one transaction) and delete `source`.
    Returns counters of what moved / merged. The caller must make sure no
    scan is in flight for either row."""
    check_mergeable(source, target)
    stats = {k: 0 for k in (
        "scans_moved", "assets_moved", "assets_merged", "findings_moved", "findings_merged",
        "findings_reopened", "subdomains_moved", "endpoints_moved", "schedule_dropped",
    )}
    async with in_transaction():
        stats["scans_moved"] = await Scan.filter(domain_id=source.id).update(domain_id=target.id)

        # Assets (+ their history). last_seen_at is auto_now: only queryset
        # update() keeps explicit timestamps, a save() would stamp "now".
        target_assets = {(a.type, a.value): a for a in await Asset.filter(domain_id=target.id)}
        for a in await Asset.filter(domain_id=source.id):
            twin = target_assets.get((a.type, a.value))
            if twin is None:
                await Asset.filter(id=a.id).update(domain_id=target.id)
                stats["assets_moved"] += 1
                continue
            fields: dict[str, Any] = {}
            if _aware(a.first_seen_at) < _aware(twin.first_seen_at):
                fields["first_seen_at"] = a.first_seen_at
                fields["first_seen_scan_id"] = a.first_seen_scan_id
            if _aware(a.last_seen_at) > _aware(twin.last_seen_at):
                fields.update(last_seen_at=a.last_seen_at, last_seen_scan_id=a.last_seen_scan_id,
                              metadata=a.metadata)
            if fields:
                await Asset.filter(id=twin.id).update(**fields)
            await AssetHistory.filter(asset_id=a.id).update(asset_id=twin.id)
            await Asset.filter(id=a.id).delete()
            stats["assets_merged"] += 1

        # Findings
        target_findings = {f.fingerprint: f for f in await Finding.filter(domain_id=target.id)}
        for f in await Finding.filter(domain_id=source.id):
            twin = target_findings.get(f.fingerprint)
            if twin is None:
                await Finding.filter(id=f.id).update(domain_id=target.id)
                stats["findings_moved"] += 1
                continue
            was_closed = twin.status == "fixed"
            values = reconcile_findings(twin, f)
            await Finding.filter(id=twin.id).update(**values)
            await Finding.filter(id=f.id).delete()
            stats["findings_merged"] += 1
            if was_closed and values["status"] == "open":
                stats["findings_reopened"] += 1

        # Legacy per-domain tables (unique per domain): keep the target's row
        for model, key, stat in ((Subdomain, "subdomain", "subdomains_moved"), (Endpoint, "path", "endpoints_moved")):
            have = {getattr(r, key) for r in await model.filter(domain_id=target.id)}
            for r in await model.filter(domain_id=source.id):
                if getattr(r, key) in have:
                    await model.filter(id=r.id).delete()
                else:
                    await model.filter(id=r.id).update(domain_id=target.id)
                    stats[stat] += 1

        # One schedule per domain: the target's wins.
        src_schedule = await Schedule.get_or_none(domain_id=source.id)
        if src_schedule is not None:
            if await Schedule.filter(domain_id=target.id).exists():
                await Schedule.filter(id=src_schedule.id).delete()
                stats["schedule_dropped"] = 1
            else:
                await Schedule.filter(id=src_schedule.id).update(domain_id=target.id)

        # Review decisions are per domain: keep both sides'.
        await Domain.filter(id=target.id).update(
            app_developers=_union_by(target.app_developers, source.app_developers, ("store", "name")),
            app_rejections=_union_by(target.app_rejections, source.app_rejections, ("store", "name")),
        )
        await Domain.filter(id=source.id).delete()
    logger.info(f"Merged domain row {source.id} into {target.id} ({target.domain}): {stats}")
    return stats


async def find_orphan_merges() -> list[tuple[Domain, Domain]]:
    """(orphan, owned) pairs safe to merge automatically: a company-less row
    whose name matches exactly one company-owned row. Ambiguous cases (several
    owners) are left for a human."""
    orphans = await Domain.filter(company_id__isnull=True)
    pairs: list[tuple[Domain, Domain]] = []
    for orphan in orphans:
        owners = [d for d in await Domain.filter(domain=orphan.domain) if d.company_id is not None]
        if len(owners) == 1:
            pairs.append((orphan, owners[0]))
        elif len(owners) > 1:
            logger.warning(f"Orphan domain row {orphan.id} ({orphan.domain}) matches {len(owners)} "
                           "company-owned rows — not merged automatically")
    return pairs

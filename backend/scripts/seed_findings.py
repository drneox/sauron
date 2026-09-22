#!/usr/bin/env python3
"""
Ad-hoc migration: seed persistent Finding rows from the completed scans
already stored in the DB.

For each domain, walks its completed full scans chronologically:
  - fingerprint = sha1(domain|module|normalized text) — same helper as the
    live pipeline (imported from main), so seeded rows merge seamlessly with
    future scan upserts.
  - first_seen = first scan that reported the finding, last_seen = last one.
  - status = open if the finding appears in the domain's latest full scan,
    fixed (auto-resolved) otherwise, with fixed_at = latest scan's
    completed_at (the moment it was detected gone).

Idempotent: re-running updates last_seen when newer scans exist and never
duplicates rows (UNIQUE(domain_id, fingerprint)).

Run from the backend directory:  ./.venv/bin/python scripts/seed_findings.py
"""
import asyncio
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Domain, Finding, Scan, close_db, init_db  # noqa: E402
from main import _finding_fingerprint, _finding_text  # noqa: E402
from modules import compliance  # noqa: E402


def _scan_time(scan: Scan) -> datetime:
    return scan.completed_at or scan.started_at or datetime.now(timezone.utc)


async def seed() -> None:
    await init_db()
    total_created = total_updated = total_fixed = 0
    domains = await Domain.all().order_by("id")
    for dom in domains:
        scans = await Scan.filter(domain_id=dom.id, status="completed").order_by("started_at", "id")
        full_scans = [
            s for s in scans
            if isinstance(s.result, dict) and s.result.get("kind", "full") == "full"
        ]
        if not full_scans:
            continue
        latest = full_scans[-1]
        # fp -> aggregate across the domain's scan history
        seen: dict[str, dict] = {}
        for scan in full_scans:
            for f in (scan.result or {}).get("findings") or []:
                if not isinstance(f, dict):
                    continue
                text = _finding_text(f.get("finding"))
                if not text:
                    continue
                module = f.get("module") or "unknown"
                fp = _finding_fingerprint(dom.domain, module, text)
                entry = seen.get(fp)
                if entry is None:
                    entry = {
                        "module": module, "text": text,
                        "first_scan": scan, "last_scan": scan,
                        "risk": "low", "category": "info",
                    }
                    seen[fp] = entry
                entry["last_scan"] = scan
                # Latest scan wins for risk/category (they can drift over time)
                entry["risk"] = f.get("risk") if f.get("risk") in ("critical", "high", "medium", "low") else "low"
                entry["category"] = f.get("category") or "info"
        created = updated = fixed = 0
        for fp, e in seen.items():
            is_current = e["last_scan"].id == latest.id
            status = "open" if is_current else "fixed"
            fixed_at = _scan_time(latest) if not is_current else None
            frameworks = compliance.frameworks_for(e["module"], e["text"])
            rec = await Finding.get_or_none(domain_id=dom.id, fingerprint=fp)
            if rec is None:
                await Finding.create(
                    domain_id=dom.id, fingerprint=fp,
                    module=e["module"], text=e["text"],
                    risk=e["risk"], category=e["category"], frameworks=frameworks,
                    status=status,
                    first_seen_scan_id=e["first_scan"].id,
                    last_seen_scan_id=e["last_scan"].id,
                    first_seen_at=_scan_time(e["first_scan"]),
                    last_seen_at=_scan_time(e["last_scan"]),
                    fixed_at=fixed_at,
                )
                created += 1
            else:
                # Idempotent re-run: only roll last_seen forward when the
                # history shows a newer sighting; never resurrect or duplicate.
                changed = False
                if rec.last_seen_scan_id != e["last_scan"].id:
                    rec.last_seen_scan_id = e["last_scan"].id
                    rec.last_seen_at = _scan_time(e["last_scan"])
                    changed = True
                if not rec.frameworks and frameworks:
                    rec.frameworks = frameworks
                    changed = True
                if changed:
                    await rec.save()
                    updated += 1
            if status == "fixed":
                fixed += 1
        total_created += created
        total_updated += updated
        total_fixed += fixed
        print(f"domain {dom.domain!r} (id={dom.id}): {len(full_scans)} full scans, "
              f"{len(seen)} unique findings -> {created} created, {updated} updated, "
              f"{fixed} auto-fixed (not in latest scan)")
    print(f"\nTOTAL: {total_created} findings seeded, {total_updated} updated, "
          f"{total_fixed} auto-fixed (absent from the latest scan of their domain)")
    await close_db()


if __name__ == "__main__":
    asyncio.run(seed())

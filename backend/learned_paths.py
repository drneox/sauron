"""Learned paths: closing the loop from the LLM's guesses back to coverage.

smart_fuzz asks the LLM for paths a static wordlist would not have (derived
from the target's own JS, stack and sector). Every guess is verified by a real
request, so nothing is invented — but a hit on ONE site says little about
whether the path is worth probing everywhere. This module keeps the hits,
and only a path that proves generic becomes a candidate for the fixed set:

  - it must look like a shared, static route, not a site's own slug or an
    action: at most 4 short segments of plain characters, no query string, no
    verb that could change state when requested with GET (logout, delete,
    cancel, pay...). The path was chosen by text the target controls, so the
    shape filter is also what keeps a hostile site from seeding the set;
  - it must have answered on 2+ distinct hosts;
  - the AI triage must not have called it public-by-design/noise (those only
    produce more findings to dismiss).

Approval is a person's decision (Settings); `learned_auto_approve` skips it.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from db import LearnedPath

logger = logging.getLogger(__name__)

MIN_HOSTS = 2
MAX_HOSTS_KEPT = 20
MAX_APPROVED_PER_SCAN = 200
_SHAPE = re.compile(r"^/(?:[a-z0-9._~-]{1,30}/?){1,4}$")
_STATE_CHANGING = re.compile(
    r"(logout|log-out|signout|sign-out|delete|remove|destroy|erase|reset|cancel|unsubscribe|"
    r"unlink|revoke|disable|deactivate|purge|wipe|checkout|payment|pay$|buy|order|submit|confirm)",
    re.I,
)
DISMISSED_VERDICTS = ("public_by_design", "noise")


def normalize(path: str) -> str:
    return (path or "").strip().lower().rstrip("/") or "/"


def is_safe_path(path: str) -> bool:
    p = normalize(path)
    if p == "/" or not _SHAPE.match(p + "/") or "?" in p or ".." in p:
        return False
    return not _STATE_CHANGING.search(p)


def is_candidate(row: Any) -> bool:
    """Seen enough, safe, and not already dismissed by the AI."""
    return (
        row.status == "seen"
        and len(row.hosts or []) >= MIN_HOSTS
        and row.ai_verdict not in DISMISSED_VERDICTS
        and is_safe_path(row.path)
    )


def hits_from_result(result: dict, known_paths: set[str]) -> list[tuple[str, int | None]]:
    """(path, status) of LLM-directed smart_fuzz hits worth remembering: found
    by a real request, not already in a static wordlist, safe to probe widely."""
    sf = ((result or {}).get("modules") or {}).get("smart_fuzz") or {}
    out: list[tuple[str, int | None]] = []
    for hit in sf.get("paths_found") or []:
        if not isinstance(hit, dict) or not hit.get("directed"):
            continue
        status = hit.get("status")
        if not isinstance(status, int) or not 200 <= status < 300:
            continue
        path = normalize(hit.get("path") or "")
        if path in known_paths or not is_safe_path(path):
            continue
        out.append((path, status))
    return out


async def record_hits(result: dict, known_paths: set[str], auto_approve: bool = False) -> int:
    """Store the scan's learnable hits; returns how many were recorded."""
    host = str((result or {}).get("domain") or "").strip().lower()
    if not host:
        return 0
    now = datetime.now(timezone.utc)
    recorded = 0
    for path, status in hits_from_result(result, known_paths):
        row = await LearnedPath.get_or_none(path=path)
        if row is None:
            row = await LearnedPath.create(path=path, hosts=[host], hits=1, last_status=status, last_seen_at=now)
        else:
            hosts = list(row.hosts or [])
            if host not in hosts and len(hosts) < MAX_HOSTS_KEPT:
                hosts.append(host)
            row.hosts, row.hits, row.last_status, row.last_seen_at = hosts, row.hits + 1, status, now
            await row.save()
        recorded += 1
        if auto_approve and is_candidate(row):
            await decide(row, "approved", "auto")
    return recorded


async def decide(row: LearnedPath, status: str, by: str) -> None:
    row.status, row.decided_by, row.decided_at = status, by, datetime.now(timezone.utc)
    await row.save()


async def approved_paths() -> list[str]:
    """What smart_fuzz adds to every scan. Re-checked against the shape rules
    on every load, so a row edited by hand can't smuggle in an unsafe path."""
    rows = await LearnedPath.filter(status="approved").order_by("path")
    return [r.path for r in rows if is_safe_path(r.path)][:MAX_APPROVED_PER_SCAN]


async def set_verdict(path: str, verdict: str) -> None:
    await LearnedPath.filter(path=normalize(path)).update(ai_verdict=verdict)

"""Identity of a finding across scans.

A finding is the same finding when it is about the same host, reported by the
same module, saying the same thing. The text a module prints also carries
details that change between runs without the finding changing:

  - the severity tag ("[HIGH] Path discovered...") — the same file rated
    differently by two runs used to become two findings;
  - the "[LLM-directed]" marker — who proposed the path says nothing about it;
  - the response size ("(HTTP 200, 1064354 bytes)") — a log file grows every
    day, a CMS page jitters by a few bytes, and each size was a new finding.

`normalize_text` strips exactly those, for the fingerprint only; the stored
text is untouched. FINGERPRINT_VERSION is bumped whenever the rules change so
a startup pass can re-key existing rows (see refingerprint_all).
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from db import AppSetting, Domain, Finding
from domain_merge import reconcile_findings

logger = logging.getLogger(__name__)

FINGERPRINT_VERSION = 2
_VERSION_KEY = "finding_fingerprint_version"

_SEVERITY_TAG = re.compile(r"^\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*")
_DIRECTED_TAG = re.compile(r"\s*\[LLM-directed\]")
_SIZE = re.compile(r",\s*\d+\s*bytes\)")


def normalize_text(text: str) -> str:
    text = _SEVERITY_TAG.sub("", text or "")
    text = _DIRECTED_TAG.sub("", text)
    text = _SIZE.sub(")", text)
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(host: str, module: str, text: str) -> str:
    return hashlib.sha1(f"{host}|{module}|{normalize_text(text)}".encode("utf-8")).hexdigest()


async def refingerprint_all() -> dict[str, int]:
    """Re-key every finding under the current rules, folding the rows that
    become the same finding (e.g. one per file size) into one. Idempotent and
    run once per FINGERPRINT_VERSION."""
    stats = {"rekeyed": 0, "merged": 0}
    domains = {d.id: d.domain for d in await Domain.all()}
    groups: dict[tuple[int, str], list[Finding]] = {}
    for f in await Finding.all():
        host = f.host or domains.get(f.domain_id, "")
        groups.setdefault((f.domain_id, fingerprint(host, f.module, f.text)), []).append(f)
    for (domain_id, new_fp), rows in groups.items():
        # The row already holding the new key (if any) stays; otherwise the
        # most recently seen one becomes the keeper.
        rows.sort(key=lambda r: (r.fingerprint != new_fp, -(r.last_seen_at.timestamp() if r.last_seen_at else 0)))
        keep, others = rows[0], rows[1:]
        values: dict[str, Any] = {}
        for other in others:
            values = reconcile_findings(keep, other)
            for k, v in values.items():
                setattr(keep, k, v)
            await Finding.filter(id=other.id).delete()
            stats["merged"] += 1
        if others:
            await Finding.filter(id=keep.id).update(**values)
        if keep.fingerprint != new_fp:
            await Finding.filter(id=keep.id).update(fingerprint=new_fp)
            stats["rekeyed"] += 1
    return stats


async def ensure_current() -> dict[str, int] | None:
    """Run the re-keying pass if the stored version is behind."""
    row = await AppSetting.get_or_none(key=_VERSION_KEY)
    if row is not None and row.value == FINGERPRINT_VERSION:
        return None
    stats = await refingerprint_all()
    await AppSetting.update_or_create(key=_VERSION_KEY, defaults={"value": FINGERPRINT_VERSION})
    logger.info(f"Finding fingerprints re-keyed to v{FINGERPRINT_VERSION}: {stats}")
    return stats

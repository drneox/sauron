"""
Audit log — persisted who-did-what trail for sensitive in-app actions.

record() is fire-and-forget by design: auditing must never break the action
it is observing, so every failure is logged and swallowed. Events are purged
by the scheduler once they are older than the `audit_retention_days` app
setting (default 90).
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Caps so a buggy caller can't write unbounded blobs into one event row.
MAX_DETAIL_KEYS = 20
MAX_DETAIL_VALUE = 500


def redact_term(term: str) -> str:
    """One-way fingerprint of a sensitive lookup term (a LeakCheck email /
    username): enough to correlate "the same term was queried again", never
    enough to read it."""
    return hashlib.sha1(term.strip().lower().encode("utf-8")).hexdigest()[:12]


def _clean_detail(detail: dict | None) -> dict | None:
    if not detail:
        return None
    out: dict[str, Any] = {}
    for key, value in list(detail.items())[:MAX_DETAIL_KEYS]:
        if isinstance(value, str) and len(value) > MAX_DETAIL_VALUE:
            value = value[:MAX_DETAIL_VALUE] + "…"
        out[str(key)] = value
    return out or None


async def record(action: str, user=None, target: str | None = None,
                 detail: dict | None = None, ip: str | None = None) -> None:
    """Persist one audit event. `user` is a User row, the DEV_USER dict, or
    None for system actions (scheduler). Never raises."""
    try:
        from db import AuditEvent  # late import: modules must not load db at import time
        user_id = None
        email = ""
        if user is not None:
            uid = getattr(user, "id", None) if not isinstance(user, dict) else user.get("id")
            email = getattr(user, "email", None) if not isinstance(user, dict) else user.get("email", "")
            user_id = uid or None  # DEV_USER's id 0 is not a real row — store email only
        await AuditEvent.create(
            user_id=user_id, user_email=email or "", action=action,
            target=(target or None) and str(target)[:255],
            detail=_clean_detail(detail), ip=ip,
        )
    except Exception:
        logger.warning(f"audit record failed for action={action}", exc_info=True)


async def purge(retention_days: int) -> int:
    """Delete events older than `retention_days`; returns the deleted count."""
    from db import AuditEvent  # late import: modules must not load db at import time
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    deleted = await AuditEvent.filter(created_at__lt=cutoff).delete()
    if deleted:
        logger.info(f"Audit purge: deleted {deleted} event(s) older than {retention_days} days")
    return deleted

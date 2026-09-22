"""
Scan-completion delta notifications.

POSTs a compact JSON summary {"text": ...} to NOTIFY_WEBHOOK_URL
(Slack / Discord / generic incoming webhook) when a completed scan produces
notable changes versus the previous one.

Environment:
  NOTIFY_WEBHOOK_URL   incoming webhook URL; unset = notifications off
  NOTIFY_ON            csv of triggers (default: all three):
      new_assets          new subdomains or JS endpoints appeared
      critical_findings   new critical/high findings appeared
      grade_change        risk grade changed vs previous scan

notify_scan_completed() is synchronous (call via asyncio.to_thread from the
async persistence path) and NEVER raises — notification failures are logged
and swallowed so they can't break the scan pipeline.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 5
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:5173")
_MAX_BULLETS = 3
_ALL_TRIGGERS = {"new_assets", "critical_findings", "grade_change"}


def _enabled_triggers() -> set[str]:
    raw = os.getenv("NOTIFY_ON", "").strip()
    if not raw:
        return set(_ALL_TRIGGERS)
    return {t.strip() for t in raw.split(",") if t.strip()}


def _new_critical_findings(scan_result: dict, changes: dict) -> list[dict]:
    """New findings (vs previous scan) whose risk is critical or high."""
    new = set(changes.get("new_findings") or [])
    if not new:
        return []
    return [
        f for f in scan_result.get("findings", [])
        if isinstance(f, dict)
        and f.get("finding") in new
        and f.get("risk") in ("critical", "high")
    ]


def _build_text(scan_result: dict, changes: dict, triggers: set[str]) -> str | None:
    domain = scan_result.get("domain", "?")
    scorecard = scan_result.get("scorecard") or {}
    grade = scorecard.get("grade", "?")
    score = scorecard.get("score", "?")
    bullets: list[str] = []

    if "new_assets" in triggers:
        new_subs = changes.get("new_subdomains") or []
        new_eps = changes.get("new_endpoints") or []
        if new_subs:
            bullets.append(f"{len(new_subs)} new subdomain(s): {', '.join(new_subs[:3])}")
        if new_eps:
            bullets.append(f"{len(new_eps)} new endpoint(s): {', '.join(e.get('path', '?') for e in new_eps[:3])}")

    if "critical_findings" in triggers:
        crit = _new_critical_findings(scan_result, changes)
        if crit:
            bullets.append(
                f"{len(crit)} new critical/high finding(s): "
                + " | ".join(f.get("finding", "")[:80] for f in crit[:2])
            )

    if "grade_change" in triggers:
        prev_grade = changes.get("previous_grade")
        if prev_grade and prev_grade != grade:
            delta = changes.get("score_delta")
            delta_str = f"{delta:+d}" if isinstance(delta, int) else "?"
            bullets.append(f"Grade changed: {prev_grade} -> {grade} (score delta {delta_str})")

    if not bullets:
        return None

    shown = bullets[:_MAX_BULLETS]
    extra = len(bullets) - len(shown)
    lines = [f"[Dumb Auditor] Scan completed: {domain} — grade {grade} (score {score})"]
    lines += [f"• {b}" for b in shown]
    if extra > 0:
        lines.append(f"• …and {extra} more change(s)")
    lines.append(f"Dashboard: {DASHBOARD_URL}")
    return "\n".join(lines)


def notify_scan_completed(scan_result: dict, changes: dict | None) -> None:
    """POST a delta summary to the configured webhook. Never raises."""
    webhook = os.getenv("NOTIFY_WEBHOOK_URL", "").strip()
    if not webhook:
        return
    try:
        changes = changes or {}
        text = _build_text(scan_result, changes, _enabled_triggers())
        if text is None:
            return
        # Direct connection on purpose: the webhook is operator infra and the
        # payload contains finding details — never through the proxy pool.
        resp = httpx.post(webhook, json={"text": text}, timeout=TIMEOUT)
        logger.info(f"[notify] webhook POST -> HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[notify] webhook delivery failed: {e}")

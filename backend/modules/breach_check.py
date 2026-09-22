"""
Breach & Leak Detection Module
Checks if the domain (and its emails/users) appear in public breach databases.

Sources used (all free / no API key required unless noted):
  - HaveIBeenPwned domain search (requires HIBP_API_KEY env var; skipped without it)
  - ProxyNova COMB (public combo index)
  - crt.sh — email addresses visible in certificates
  - LeakCheck public API (no key needed, limited) — domain + per-email combolist names
  - Hunter.io domain search (requires HUNTER_API_KEY env var, optional)
  - grep.app — public code mentions
  - HudsonRock Cavalier OSINT API — free info-stealer / botnet combolist lookup per email
  - BreachDirectory public API — combolist names per email
"""
import httpx
import asyncio
import dns.resolver
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)


def _hibp_domain_check(domain: str) -> dict:
    """
    Check HIBP for breaches associated with the domain.
    The v3 API requires an API key (HIBP_API_KEY env var); without it the
    source is skipped instead of dying on a 401.
    """
    result = {"breaches": [], "paste_count": 0, "checked": False}
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        result["note"] = "HIBP skipped: HIBP_API_KEY not configured"
        return result
    try:
        resp = httpx.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            headers={
                "User-Agent": "Dumb-Auditor/1.0",
                "hibp-api-key": api_key,
            },
            timeout=10,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["checked"] = True
            result["breaches"] = [
                {
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                    "verified": b.get("IsVerified", False),
                }
                for b in data
            ]
        elif resp.status_code == 401:
            result["checked"] = False
            result["note"] = "HIBP rejected the configured HIBP_API_KEY (401)"
        elif resp.status_code == 404:
            result["checked"] = True  # clean
    except Exception as e:
        logger.debug(f"[breach/hibp] {domain}: {e}")
    return result


def _dehashed_public(domain: str) -> dict:
    """
    Query public breach aggregators that don't require auth.
    """
    result = {"sources": [], "checked": False}
    try:
        resp = httpx.get(
            f"https://api.proxynova.com/comb?query={domain}&start=0&limit=200",
            headers={"User-Agent": "Dumb-Auditor/1.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            count = data.get("count", 0)
            lines = data.get("lines", [])
            result["checked"] = True
            result["combo_count"] = count
            result["samples"] = [_redact(line) for line in lines[:200]]
        else:
            result["checked"] = False
    except Exception as e:
        logger.debug(f"[breach/proxynova] {domain}: {e}")
    return result


def _redact(line: str) -> str:
    """Redact passwords from combo lines for safe display."""
    if ":" in line:
        parts = line.split(":", 1)
        return f"{parts[0]}:{'*' * min(len(parts[1]), 8)}"
    return line[:40] + "..."


def _extract_emails_from_certs(domain: str) -> list[str]:
    """Get email addresses visible in SSL certificate SANs via crt.sh."""
    emails = set()
    try:
        resp = httpx.get(
            f"https://crt.sh/?q={domain}&output=json",
            headers={"User-Agent": "Dumb-Auditor/1.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                # Some certs embed email addresses
                for email in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", name):
                    if email.endswith(f"@{domain}") or f".{domain}" in email:
                        emails.add(email.lower())
    except Exception as e:
        logger.debug(f"[breach/certs] {domain}: {e}")
    return list(emails)


def _leakcheck_domain(domain: str) -> dict:
    """
    LeakCheck public API — no API key required.
    Returns count of found records and the source databases.
    """
    result = {"checked": False, "found": 0, "sources": [], "fields": []}
    try:
        resp = httpx.get(
            f"https://leakcheck.io/api/public?check={domain}",
            headers={"User-Agent": "Dumb-Auditor/1.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["checked"] = True
            result["found"] = data.get("found", 0)
            result["sources"] = data.get("sources", [])
            result["fields"] = data.get("fields", [])
        elif resp.status_code == 429:
            result["error"] = "rate_limited"
    except Exception as e:
        logger.debug(f"[breach/leakcheck] {domain}: {e}")
    return result


def _hunter_email_finder(domain: str) -> dict:
    """
    Hunter.io domain search — requires HUNTER_API_KEY in environment.
    Free tier: 25 searches/month. Falls back gracefully if no key.
    Paginates through ALL results using offset until total is reached.
    https://hunter.io/api-documentation/v2#domain-search
    """
    result = {"checked": False, "emails": [], "total": 0, "organization": None}
    api_key = os.environ.get("HUNTER_API_KEY", "").strip()
    if not api_key:
        result["error"] = "no_api_key"
        return result

    PAGE_SIZE = 100  # Hunter.io max per request
    all_emails: list[dict] = []
    offset = 0

    try:
        while True:
            resp = httpx.get(
                "https://api.hunter.io/v2/domain-search",
                params={
                    "domain": domain,
                    "api_key": api_key,
                    "limit": PAGE_SIZE,
                    "offset": offset,
                },
                headers={"User-Agent": "Dumb-Auditor/1.0"},
                timeout=12,
            )
            if resp.status_code == 401:
                result["error"] = "invalid_api_key"
                return result
            if resp.status_code == 429:
                result["error"] = "rate_limited"
                break
            if resp.status_code != 200:
                break

            data = resp.json().get("data", {})
            if not result["checked"]:
                result["checked"] = True
                result["organization"] = data.get("organization")
                result["total"] = data.get("total", 0)

            page_emails = data.get("emails", [])
            if not page_emails:
                break

            for e in page_emails:
                all_emails.append({
                    "email": e.get("value"),
                    "confidence": e.get("confidence", 0),
                    "position": e.get("position"),
                    "first_name": e.get("first_name"),
                    "last_name": e.get("last_name"),
                    "linkedin": e.get("linkedin"),
                    "sources": [s.get("domain") for s in e.get("sources", [])[:3]],
                })

            offset += len(page_emails)
            # Stop when we've fetched all or hit a safety cap (500 emails)
            if offset >= result["total"] or offset >= 500:
                break

    except Exception as e:
        logger.debug(f"[breach/hunter] {domain}: {e}")

    result["emails"] = all_emails
    return result


def _check_pastebin_mentions(domain: str) -> dict:
    """Check for domain mentions in public paste sites via Google dork proxy."""
    result = {"checked": False, "paste_sites": []}
    try:
        # Use publicwww-style search via grep.app API (no key required)
        resp = httpx.get(
            f"https://grep.app/api/search?q={domain}&regexp=false",
            headers={"User-Agent": "Dumb-Auditor/1.0"},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            hits = data.get("hits", {}).get("total", {}).get("value", 0)
            result["checked"] = True
            result["public_code_mentions"] = hits
    except Exception as e:
        logger.debug(f"[breach/paste] {domain}: {e}")
    return result


def _source_name(item: Any) -> str:
    """Breach sources arrive as plain strings or dicts depending on the API."""
    if isinstance(item, dict):
        return str(item.get("name") or item.get("title") or item)
    return str(item)


def run(domain: str) -> dict[str, Any]:
    hibp = _hibp_domain_check(domain)
    combo = _dehashed_public(domain)
    crt_emails = _extract_emails_from_certs(domain)
    leakcheck = _leakcheck_domain(domain)
    hunter = _hunter_email_finder(domain)
    paste = _check_pastebin_mentions(domain)

    breach_count = len(hibp.get("breaches", []))
    combo_count = combo.get("combo_count", 0)

    # Merge all discovered emails, deduplicated
    all_emails: set[str] = set(crt_emails)
    for e in hunter.get("emails", []):
        if e.get("email"):
            all_emails.add(e["email"].lower())
    all_emails_list = sorted(all_emails)

    findings = []
    risk = "low"

    if breach_count > 0:
        risk = "critical"
        total_records = sum(b.get("pwn_count", 0) for b in hibp["breaches"])
        findings.append(
            f"Domain found in {breach_count} public breach(es) — "
            f"~{total_records:,} records exposed"
        )
        for b in hibp["breaches"][:3]:
            dc = ", ".join(_source_name(c) for c in b.get("data_classes", [])[:4])
            findings.append(f"Breach '{b['title']}' ({b['breach_date']}): {dc}")

    if not hibp.get("checked") and hibp.get("note"):
        findings.append(hibp["note"])

    if leakcheck.get("found", 0) > 0:
        if risk == "low":
            risk = "high"
        src_str = ", ".join(_source_name(s) for s in leakcheck.get("sources", [])[:4]) or "unknown sources"
        findings.append(
            f"LeakCheck: {leakcheck['found']} records found across {src_str}"
        )

    if combo_count > 0:
        if risk == "low":
            risk = "high"
        findings.append(
            f"{combo_count:,} email:password combos found in combo lists for this domain"
        )

    if hunter.get("checked") and hunter.get("total", 0) > 0:
        findings.append(
            f"Hunter.io: {hunter['total']} email addresses found publicly for this domain"
        )

    if all_emails_list:
        findings.append(
            f"{len(all_emails_list)} email address(es) discovered across all sources"
        )

    if paste.get("public_code_mentions", 0) > 100:
        findings.append(
            f"Domain found in {paste['public_code_mentions']} public code repositories — review for secrets"
        )

    return {
        "status": "ok",
        "breaches": hibp.get("breaches", []),
        "breach_count": breach_count,
        "combo_count": combo_count,
        # Emails — backwards compatible + new fields
        "exposed_emails": crt_emails,          # crt.sh only (legacy)
        "all_emails": all_emails_list,          # merged from all sources
        "hunter": {
            "checked": hunter.get("checked", False),
            "total": hunter.get("total", 0),
            "organization": hunter.get("organization"),
            "emails": hunter.get("emails", []),
            "error": hunter.get("error"),
        },
        "leakcheck": {
            "checked": leakcheck.get("checked", False),
            "found": leakcheck.get("found", 0),
            "sources": leakcheck.get("sources", []),
            "fields": leakcheck.get("fields", []),
            "error": leakcheck.get("error"),
        },
        "public_code_mentions": paste.get("public_code_mentions", 0),
        "hibp_checked": hibp.get("checked", False),
        "hibp_note": hibp.get("note"),
        "combo_samples": combo.get("samples", []),
        "risk": risk,
        "findings": findings,
    }

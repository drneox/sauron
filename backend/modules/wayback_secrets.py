"""
wayback_secrets.py — Wayback Machine historical exposure scanner.

Uses the Wayback CDX API to find URLs archived for the target domain that
match sensitive file / path patterns, then spot-checks a sample of those
snapshots for exposed credentials, tokens, and configuration.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx

TIMEOUT     = httpx.Timeout(15.0, connect=8.0)
CONCURRENCY = 5
CDX_LIMIT   = 500       # max CDX results per query
SNAPSHOT_SAMPLE = 8     # max snapshots to retrieve content from

_CDX_BASE = "http://web.archive.org/cdx/search/cdx"
_WBM_BASE = "http://web.archive.org/web"

# ── Sensitive path patterns ────────────────────────────────────────────────────
_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (regex, label, severity)
    (r'\.env(\.|$)',                       ".env file",                "critical"),
    (r'\.env\.(local|prod|staging|dev)',   ".env variant",             "critical"),
    (r'credentials?\.(json|yaml|yml|xml)', "Credentials file",        "critical"),
    (r'secrets?\.(json|yaml|yml|txt)',     "Secrets file",             "critical"),
    (r'config\.(json|yaml|yml|php|rb)',    "Config file",              "high"),
    (r'database\.(yml|yaml|json|sql)',     "Database config",          "high"),
    (r'settings\.(py|json|yaml|php)',      "Settings file",            "high"),
    (r'wp-config\.php',                    "WordPress config",         "critical"),
    (r'\.git/(config|HEAD|COMMIT_EDITMSG)',"Git metadata",             "high"),
    (r'\.gitconfig',                       "Git config",               "high"),
    (r'id_rsa(\.pub)?$',                   "SSH private key",          "critical"),
    (r'(private|priv).*\.pem',             "Private key/cert",         "critical"),
    (r'backup.*\.(sql|gz|tar|zip|tgz)',    "Database backup",          "high"),
    (r'dump.*\.(sql|gz)',                   "DB dump",                  "high"),
    (r'phpinfo\.php',                       "phpinfo exposure",         "high"),
    (r'server-status',                      "Apache server-status",     "high"),
    (r'elmah\.axd',                         "ELMAH error log",          "high"),
    (r'trace\.axd',                         "ASP.NET trace",            "high"),
    (r'(access|error)[-_\.]log',           "Log file",                 "medium"),
    (r'(auth|oauth).*token',               "Auth token URL",            "high"),
    (r'api[_-]?key',                        "API key in URL",           "high"),
    (r'password',                           "Password in URL",          "high"),
    (r'passwd',                             "Passwd file",              "high"),
    (r'shadow',                             "Shadow file",              "critical"),
    (r'\.htpasswd',                         ".htpasswd",                "critical"),
]

# ── Content secret patterns (scan retrieved snapshots) ───────────────────────
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
     "API key",          "high"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
     "Secret key",       "high"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})',
     "Password",         "critical"),
    (r'(?i)(aws_access_key_id|access_key)\s*[=:]\s*["\']?([A-Z0-9]{16,20})',
     "AWS access key",   "critical"),
    (r'AKIA[0-9A-Z]{16}',
     "AWS key pattern",  "critical"),
    (r'(?i)(db_pass|database_password)\s*[=:]\s*["\']?([^\s"\']{6,})',
     "DB password",      "critical"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "Private key",      "critical"),
    (r'(?i)(bearer|token)\s+[A-Za-z0-9\-._~+/]{20,}',
     "Bearer token",     "high"),
    (r'(?i)ghp_[A-Za-z0-9]{36}',
     "GitHub PAT",       "critical"),
    (r'(?i)sk-[A-Za-z0-9]{48}',
     "OpenAI key",       "critical"),
    (r'(?i)(slack_token|xoxb-|xoxp-)[A-Za-z0-9\-]{20,}',
     "Slack token",      "critical"),
]


def _classify_url(url: str) -> tuple[str, str] | None:
    """Return (label, severity) if url matches a sensitive pattern, else None."""
    for pattern, label, sev in _SENSITIVE_PATHS:
        if re.search(pattern, url, re.IGNORECASE):
            return label, sev
    return None


def _scan_content(content: str, url: str) -> list[dict]:
    """Scan text content for secret patterns."""
    hits = []
    for pattern, label, sev in _SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            snippet = content[max(0, m.start() - 20): m.end() + 20]
            # Redact actual secret value
            snippet = re.sub(r'(password|passwd|secret|key|token)\s*[=:]\s*["\']?[^\s"\']{4}',
                             lambda x: x.group(0)[:30] + "***", snippet, flags=re.I)
            hits.append({
                "secret_type": label,
                "severity":    sev,
                "url":         url,
                "snippet":     snippet[:120],
            })
            break   # one hit per pattern per file is enough
    return hits


async def _fetch_cdx(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Fetch CDX index for domain+wildcard, return list of {url, timestamp}."""
    params = {
        "url":      f"*.{domain}/*",
        "output":   "json",
        "fl":       "original,timestamp,statuscode",
        "collapse": "urlkey",
        "limit":    str(CDX_LIMIT),
        "filter":   "statuscode:200",
    }
    try:
        r = await client.get(_CDX_BASE, params=params)
        r.raise_for_status()
        rows = r.json()
        if not rows or len(rows) < 2:
            return []
        headers = rows[0]   # ["original", "timestamp", "statuscode"]
        return [dict(zip(headers, row)) for row in rows[1:]]
    except Exception:
        return []


async def _fetch_snapshot(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    url: str,
    timestamp: str,
) -> tuple[str, str]:
    """Fetch raw Wayback snapshot content."""
    wayback_url = f"{_WBM_BASE}/{timestamp}if_/{url}"
    async with sem:
        try:
            r = await client.get(wayback_url)
            return url, r.text[:16384]
        except Exception:
            return url, ""


async def _run_async(domain: str) -> dict[str, Any]:
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
    ) as client:
        cdx_rows = await _fetch_cdx(client, domain)

    # Classify all URLs
    sensitive_urls: list[dict] = []
    seen_urls: set[str] = set()

    for row in cdx_rows:
        url = row.get("original", "")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        match = _classify_url(url)
        if match:
            label, sev = match
            sensitive_urls.append({
                "url":       url,
                "timestamp": row.get("timestamp", ""),
                "label":     label,
                "severity":  sev,
            })

    # Sort: critical first, then high
    _order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    sensitive_urls.sort(key=lambda x: _order.get(x["severity"], 0), reverse=True)

    # Deduped sample of all indexed URLs for the report (historical surface)
    indexed_sample: list[dict] = []
    _sampled: set[str] = set()
    for row in cdx_rows:
        u = row.get("original", "")
        if u and u not in _sampled:
            _sampled.add(u)
            indexed_sample.append({"url": u, "timestamp": row.get("timestamp", "")})
        if len(indexed_sample) >= 1000:
            break

    # Fetch content of top sample to look for secrets
    secrets_found: list[dict] = []
    to_fetch = sensitive_urls[:SNAPSHOT_SAMPLE]

    if to_fetch:
        sem = asyncio.Semaphore(CONCURRENCY)
        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
        ) as client:
            tasks = [
                _fetch_snapshot(client, sem, item["url"], item["timestamp"])
                for item in to_fetch
            ]
            contents = await asyncio.gather(*tasks)

        for url, content in contents:
            if content:
                secrets_found.extend(_scan_content(content, url))

    # Deduplicate secrets
    secret_keys = set()
    unique_secrets: list[dict] = []
    for s in secrets_found:
        k = (s["secret_type"], s["url"])
        if k not in secret_keys:
            secret_keys.add(k)
            unique_secrets.append(s)

    # Risk
    risk = "low"
    if any(s["severity"] == "critical" for s in unique_secrets):
        risk = "critical"
    elif any(s["severity"] == "high" for s in unique_secrets):
        risk = "high"
    elif unique_secrets:
        risk = "medium"
    elif any(u["severity"] in ("critical", "high") for u in sensitive_urls):
        risk = "medium"
    elif sensitive_urls:
        risk = "low"

    findings = []
    for s in unique_secrets:
        findings.append(
            f"[{s['severity'].upper()}] {s['secret_type']} in archived snapshot of {s['url']}"
        )
    for u in sensitive_urls[:10]:
        if not any(s["url"] == u["url"] for s in unique_secrets):
            findings.append(
                f"[{u['severity'].upper()}] {u['label']} archived: {u['url']}"
            )

    return {
        "status":           "ok",
        "urls_indexed":     len(cdx_rows),
        "sensitive_urls":   sensitive_urls[:50],   # cap output
        "sensitive_count":  len(sensitive_urls),
        "indexed_urls":     indexed_sample,
        "secrets_found":    unique_secrets,
        "secret_count":     len(unique_secrets),
        "snapshots_fetched": len(to_fetch),
        "risk":             risk,
        "findings":         findings,
    }


def run(domain: str) -> dict[str, Any]:
    try:
        return asyncio.run(_run_async(domain))
    except Exception as exc:
        return {
            "status": "error", "error": str(exc),
            "urls_indexed": 0, "sensitive_urls": [], "sensitive_count": 0,
            "indexed_urls": [], "secrets_found": [], "secret_count": 0,
            "snapshots_fetched": 0,
            "risk": "low", "findings": [],
        }

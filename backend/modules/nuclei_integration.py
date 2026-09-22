"""
nuclei_integration.py — Nuclei vulnerability scanner integration.

Runs Nuclei against the target domain using curated template categories.
Nuclei is optional; if not installed the module returns status='skipped'.

Install: https://github.com/projectdiscovery/nuclei (go install or apt/brew)

Templates used (auto-downloaded by nuclei on first run):
  - cves/          → CVE-based checks
  - exposures/     → Sensitive file/data exposures
  - misconfiguration/ → Server misconfigurations
  - takeovers/     → Subdomain takeover detection
  - default-logins/ → Default credentials checks

Output is JSONL; each line is a finding.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

NUCLEI_TIMEOUT = 120   # seconds max for the entire nuclei run
NUCLEI_BINARY  = "nuclei"

# Templates to run (passed as -t flags, comma-separated)
_TEMPLATE_TAGS = "cve,exposure,misconfig,takeover,default-login"

# Nuclei severity → our risk mapping
_SEV_MAP = {
    "info":     "low",
    "low":      "low",
    "medium":   "medium",
    "high":     "high",
    "critical": "critical",
    "unknown":  "low",
}


def _nuclei_available() -> str | None:
    """Return path to nuclei binary or None if not found."""
    path = shutil.which(NUCLEI_BINARY)
    if path:
        return path
    # Common install locations
    for candidate in [
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        str(Path.home() / "go" / "bin" / "nuclei"),
        str(Path.home() / ".local" / "bin" / "nuclei"),
    ]:
        if Path(candidate).exists():
            return candidate
    return None


def _parse_jsonl(output: str, domain: str) -> list[dict]:
    """Parse nuclei JSONL output into structured findings."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info     = item.get("info", {})
        severity = info.get("severity", "unknown").lower()
        name     = info.get("name", item.get("template-id", "unknown"))
        desc     = info.get("description", "")
        cves     = info.get("classification", {}).get("cve-id", []) or []
        ref      = info.get("reference", []) or []
        matched  = item.get("matched-at", item.get("host", domain))
        tags     = info.get("tags", [])

        findings.append({
            "template_id": item.get("template-id", ""),
            "name":        name,
            "severity":    severity,
            "description": desc[:300] if desc else "",
            "matched_at":  matched,
            "cve_ids":     cves if isinstance(cves, list) else [cves],
            "tags":        tags if isinstance(tags, list) else [],
            "references":  ref[:3] if isinstance(ref, list) else [],
        })
    return findings


async def _run_nuclei_async(domain: str, binary: str) -> dict[str, Any]:
    target = f"https://{domain}"
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        out_file = f.name

    cmd = [
        binary,
        "-target",    target,
        "-tags",      _TEMPLATE_TAGS,
        "-severity",  "low,medium,high,critical",
        "-json-export", out_file,
        "-silent",
        "-no-color",
        "-timeout",   "5",       # per-request timeout in seconds
        "-bulk-size", "10",
        "-concurrency", "10",
        "-rate-limit", "50",
        "-retries",   "0",
    ]

    logger.info(f"Running nuclei against {domain}: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=NUCLEI_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning(f"Nuclei timed out after {NUCLEI_TIMEOUT}s for {domain}")
            return _build_result([], domain, timed_out=True)
    except Exception as exc:
        return {
            "status": "error", "error": str(exc),
            "findings_count": 0, "findings": [], "by_severity": {},
            "risk": "low", "findings": [],
        }

    # Read JSON export file
    raw = ""
    try:
        raw = Path(out_file).read_text()
        Path(out_file).unlink(missing_ok=True)
    except Exception:
        pass

    items = _parse_jsonl(raw, domain)
    return _build_result(items, domain)


def _build_result(items: list[dict], domain: str, timed_out: bool = False) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for item in items:
        sev = item["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    risk = "low"
    if by_severity.get("critical"):
        risk = "critical"
    elif by_severity.get("high"):
        risk = "high"
    elif by_severity.get("medium"):
        risk = "medium"

    findings_text = [
        f"[{item['severity'].upper()}] {item['name']} at {item['matched_at']}"
        + (f" ({', '.join(item['cve_ids'])})" if item['cve_ids'] else "")
        for item in items
    ]

    return {
        "status":         "timed_out" if timed_out else "ok",
        "findings_detail": items,
        "findings_count":  len(items),
        "by_severity":     by_severity,
        "risk":            risk,
        "findings":        findings_text,
    }


def run(domain: str) -> dict[str, Any]:
    binary = _nuclei_available()
    if not binary:
        return {
            "status":         "skipped",
            "reason":         "nuclei binary not found — install from https://github.com/projectdiscovery/nuclei",
            "findings_detail": [],
            "findings_count":  0,
            "by_severity":    {},
            "risk":           "low",
            "findings":       [],
        }
    try:
        return asyncio.run(_run_nuclei_async(domain, binary))
    except Exception as exc:
        return {
            "status": "error", "error": str(exc),
            "findings_detail": [], "findings_count": 0,
            "by_severity": {}, "risk": "low", "findings": [],
        }

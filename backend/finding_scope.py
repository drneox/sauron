"""What a scan is entitled to close.

A finding belongs to a HOST (its `host` column; the fingerprint already
hashes it). Auto-resolving "everything this scan did not see" is only valid
for what the scan actually re-checked, which used to be the bug: a full scan
of the apex swept the open findings of every subdomain it never probed (they
are re-checked by separate host scans), so a still-exposed file on
`sub.example.com` flipped to "fixed" overnight and only came back whenever
its host happened to be rescanned.

A finding is swept only when BOTH hold:
  - its host was covered by this scan (the scan's own target, plus the
    subdomains the chained evaluation probed alive during a full scan);
  - the module that reports it ran to completion in this scan — an error, a
    skip, a nuclei timeout or a WAF-truncated fuzz is "unknown", not "gone".
"""
from __future__ import annotations

from typing import Any


def modules_that_ran(result: dict) -> set[str]:
    """Modules of this scan whose silence means "not there anymore"."""
    ran: set[str] = set()
    for name, mod in (result.get("modules") or {}).items():
        if not isinstance(mod, dict):
            continue
        if mod.get("status") not in (None, "ok"):   # error / skipped / timed_out
            continue
        if name == "smart_fuzz" and mod.get("waf_blocked"):
            continue                                  # results are a lower bound
        ran.add(name)
    if result.get("agent_status") == "ok":
        ran.add("agent")
    return ran


def covered_hosts(result: dict, apex: str) -> set[str]:
    """Hosts this scan actually evaluated."""
    hosts = {str(result.get("domain") or apex).strip().lower()}
    evaluated = ((result.get("modules") or {}).get("subdomain_eval") or {}).get("evaluated") or []
    for entry in evaluated:
        if isinstance(entry, dict) and entry.get("alive") and entry.get("subdomain"):
            hosts.add(str(entry["subdomain"]).strip().lower())
    return hosts


def finding_host_of(finding: Any, apex: str) -> str:
    """Host a stored finding is about; rows from before the column existed
    (NULL) were domain-level, i.e. the apex."""
    return str(getattr(finding, "host", None) or apex).strip().lower()


def stale_findings(candidates: list, seen_fps: set[str], result: dict, apex: str) -> list:
    """The open findings (module-filtered by the caller or not) this scan is
    entitled to auto-resolve."""
    ran = modules_that_ran(result)
    covered = covered_hosts(result, apex)
    return [
        f for f in candidates
        if f.fingerprint not in seen_fps
        and f.module in ran
        and finding_host_of(f, apex) in covered
    ]

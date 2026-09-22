"""
Chained evaluation — when a scan discovers NEW live subdomains (not seen in the
previous scan), they automatically get a light evaluation: alive probe, security
headers, tech fingerprint and JS mining (where leaked secrets live). With fuzz
enabled (chain_eval_fuzz setting), each alive host also gets a light fuzz pass:
exposed files and admin panel discovery. Candidate secrets found are handed to
secret_verification for read-only validation.
"""
import logging
from typing import Any

from modules import headers_check, tech_fingerprint, js_secrets, secret_verification
from modules import exposed_files, admin_discovery
from modules.common import fetch

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 8

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: RISK_ORDER.get(r, 0))


def _probe_alive(target: str) -> tuple[bool, int | None, str | None]:
    """Try https then http. Returns (alive, status_code, final_base_url)."""
    for scheme in ("https", "http"):
        try:
            r = fetch(f"{scheme}://{target}/", timeout=PROBE_TIMEOUT, max_bytes=200_000)
            return True, r.status_code, f"{scheme}://{target}"
        except Exception:
            continue
    return False, None, None


def run(domain: str, targets: list[str], fuzz: bool = True) -> dict[str, Any]:
    """Evaluate newly discovered subdomains. targets are already filtered
    (new + alive-looking) and capped by the caller. fuzz gates the light fuzz
    step (exposed files + admin panels) per alive host."""
    evaluated: list[dict] = []
    findings: list[str] = []
    merged_raw_keys: list[dict] = []

    for target in targets:
        entry: dict[str, Any] = {"subdomain": target, "alive": False, "risk": "low"}
        alive, status_code, base = _probe_alive(target)
        if not alive:
            entry["note"] = "no HTTP response"
            evaluated.append(entry)
            continue

        entry["alive"] = True
        entry["http_status"] = status_code
        risks: list[str] = ["low"]

        steps: list[tuple[str, Any]] = [
            ("headers", headers_check), ("tech", tech_fingerprint), ("js_secrets", js_secrets),
        ]
        if fuzz:
            steps += [("exposed", exposed_files), ("admin", admin_discovery)]

        for label, mod in steps:
            try:
                r = mod.run(target)
                entry[label] = {"risk": r.get("risk", "low"), "findings": (r.get("findings") or [])[:5]}
                risks.append(r.get("risk", "low"))
                if label == "js_secrets":
                    raw = r.pop("_raw", None)
                    if raw and raw.get("candidate_keys"):
                        merged_raw_keys.extend(raw["candidate_keys"])
            except Exception as e:
                entry[label] = {"status": "error", "error": str(e)}

        entry["risk"] = _max_risk(*risks)
        evaluated.append(entry)
        labels = ("headers", "tech", "js_secrets") + (("exposed", "admin") if fuzz else ())
        sub_findings = [f for k in labels for f in (entry.get(k, {}).get("findings") or [])]
        for f in sub_findings[:3]:
            findings.append(f"[{target}] {f}")
        if entry["risk"] in ("high", "critical"):
            findings.append(f"New subdomain {target} evaluated as {entry['risk'].upper()} risk")

    # Verify any candidate secrets mined across all new subdomains (read-only)
    verification: dict[str, Any] | None = None
    if merged_raw_keys:
        try:
            verification = secret_verification.run(domain, {"candidate_keys": merged_raw_keys})
            for f in verification.get("findings", []):
                findings.append(f"[secret verification] {f}")
        except Exception as e:
            logger.warning(f"[subdomain_eval] secret verification failed: {e}")

    overall = _max_risk(*[e["risk"] for e in evaluated]) if evaluated else "low"
    if verification and verification.get("risk") in ("high", "critical"):
        overall = _max_risk(overall, verification["risk"])

    alive_count = sum(1 for e in evaluated if e["alive"])
    if evaluated:
        findings.insert(0, f"Chained evaluation: {alive_count}/{len(evaluated)} new subdomain(s) alive and evaluated")

    return {
        "status": "ok",
        "evaluated": evaluated,
        "evaluated_count": len(evaluated),
        "alive_count": alive_count,
        "secret_verification": verification,
        "risk": overall,
        "findings": findings,
    }


def skipped(reason: str) -> dict[str, Any]:
    return {
        "status": "skipped", "reason": reason, "evaluated": [], "evaluated_count": 0,
        "alive_count": 0, "secret_verification": None, "risk": "low", "findings": [],
    }

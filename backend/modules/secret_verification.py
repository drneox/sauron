"""
Secret Verification Module
Actively verifies candidate API keys discovered in JS bundles against the cloud
gateways referenced by the target's own code (read-only GETs only), and performs
offline analysis of JWT tokens found. All reported values are redacted.
"""
import base64
import json
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 8
MAX_KEYS = 5
MAX_HOSTS = 3
APIM_HEADER = "Ocp-Apim-Subscription-Key"


def _redact(value: str) -> str:
    return value[:6] + "***" + value[-3:] if len(value) > 12 else "***"


def _b64url_decode(segment: str) -> dict:
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def _analyze_jwt(token: str) -> dict:
    """Decode a JWT without verifying its signature and flag common issues."""
    result: dict[str, Any] = {
        "key": _redact(token), "alg": None, "iss": None, "tenant": None,
        "exp": None, "issues": [],
    }
    parts = token.split(".")
    if len(parts) != 3:
        result["issues"].append("malformed JWT")
        return result
    try:
        header = _b64url_decode(parts[0])
        payload = _b64url_decode(parts[1])
    except Exception as e:
        result["issues"].append(f"could not decode: {e}")
        return result
    alg = header.get("alg")
    result["alg"] = alg
    result["iss"] = payload.get("iss")
    result["tenant"] = payload.get("tid") or payload.get("tenant")
    result["exp"] = payload.get("exp")
    if alg and str(alg).lower() == "none":
        result["issues"].append("alg 'none' — token is unsigned")
    exp = payload.get("exp")
    if exp is None:
        result["issues"].append("no expiration (exp) claim")
    elif isinstance(exp, (int, float)) and exp < time.time():
        result["issues"].append("token is expired")
    return result


def _verify_apim_key(host: str, key: str) -> dict:
    """Single read-only GET against an APIM gateway root with the candidate key.
    A wrong key is rejected at the gateway with 401 'invalid subscription key';
    any other response means the key passed gateway validation."""
    try:
        r = httpx.get(
            f"https://{host}/", timeout=TIMEOUT, verify=False,
            headers={APIM_HEADER: key},
        )
        body = r.text.lower()
        if r.status_code == 401 and ("subscription key" in body or "access denied" in body):
            verdict = "invalid"
        else:
            verdict = "valid"
        evidence = f"HTTP {r.status_code} with key (bad keys get 401 invalid-key at the gateway)"
    except Exception as e:
        verdict = "unknown"
        evidence = f"network error: {e}"
    return {"host": host, "verdict": verdict, "evidence": evidence}


def run(domain: str, raw: dict | None = None) -> dict[str, Any]:
    if not raw or not raw.get("candidate_keys"):
        return {
            "status": "skipped",
            "verified": [],
            "jwt_analysis": [],
            "valid_count": 0,
            "risk": "low",
            "findings": ["No candidate keys to verify"],
        }

    candidates = raw["candidate_keys"]

    # ── Active verification: APIM subscription keys vs *.azure-api.net gateways
    verified: list[dict] = []
    apim_candidates = [c for c in candidates if "APIM" in c.get("type", "")][:MAX_KEYS]
    for c in apim_candidates:
        hosts = [h for h in c.get("host_hints", []) if h.endswith(".azure-api.net")][:MAX_HOSTS]
        for host in hosts:
            logger.info(f"Verifying candidate APIM key against {host} (read-only GET)")
            res = _verify_apim_key(host, c["value"])
            verified.append({
                "type": c["type"],
                "key": _redact(c["value"]),
                "host": host,
                "verdict": res["verdict"],
                "evidence": res["evidence"],
            })

    # ── Offline JWT analysis
    jwt_analysis = [
        _analyze_jwt(c["value"]) for c in candidates if c.get("type") == "JWT Token"
    ]

    valid_count = sum(1 for v in verified if v["verdict"] == "valid")
    invalid_count = sum(1 for v in verified if v["verdict"] == "invalid")
    unknown_count = sum(1 for v in verified if v["verdict"] == "unknown")

    findings: list[str] = []
    if valid_count:
        ok_hosts = sorted({v["host"] for v in verified if v["verdict"] == "valid"})
        findings.append(
            f"{valid_count} candidate key(s) VERIFIED as VALID against Azure APIM gateway(s) "
            f"({', '.join(ok_hosts)}) — the gateway accepted the key"
        )
    if invalid_count:
        findings.append(f"{invalid_count} candidate key(s) rejected by APIM gateway (401 invalid subscription key)")
    if unknown_count:
        findings.append(f"{unknown_count} verification attempt(s) inconclusive (network errors)")
    if not apim_candidates:
        findings.append("No APIM-type candidate keys to verify")
    elif not verified:
        findings.append("No *.azure-api.net hosts found in target JS to verify APIM candidates against")
    for j in jwt_analysis:
        for issue in j["issues"]:
            findings.append(f"JWT issue ({j['key']}): {issue}")

    if valid_count:
        risk = "critical"
    elif candidates:
        risk = "high"
    else:
        risk = "low"

    return {
        "status": "ok",
        "verified": verified,
        "jwt_analysis": jwt_analysis,
        "valid_count": valid_count,
        "risk": risk,
        "findings": findings or ["Candidate keys present but nothing could be verified"],
    }

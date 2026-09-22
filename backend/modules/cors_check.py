"""
CORS Security Check Module
Tests Cross-Origin Resource Sharing policy misconfiguration
"""
import logging
from typing import Any

from modules.common import fetch, make_client

logger = logging.getLogger(__name__)

TIMEOUT = 10
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def _test_cors(base_url: str) -> dict:
    results = []
    reflected_origin = False
    allows_null = False
    allows_credentials_wildcard = False
    misconfigured = False

    with make_client(timeout=TIMEOUT) as client:
        for origin in TEST_ORIGINS:
            try:
                resp = fetch(base_url, client=client, headers={"Origin": origin})
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                acam = resp.headers.get("Access-Control-Allow-Methods", "")

                entry = {
                    "tested_origin": origin,
                    "acao": acao or None,
                    "allow_credentials": acac == "true",
                    "allow_methods": acam or None,
                    "reflected": acao == origin,
                    "wildcard": acao == "*",
                }

                if acao == origin:
                    reflected_origin = True
                if origin == "null" and acao == "null":
                    allows_null = True
                if acao == "*" and acac == "true":
                    allows_credentials_wildcard = True

                results.append(entry)
            except Exception as e:
                logger.debug(f"CORS test failed for {origin}: {e}")
                results.append({"tested_origin": origin, "error": str(e)})

    if reflected_origin or allows_null or allows_credentials_wildcard:
        misconfigured = True

    return {
        "tests": results,
        "reflected_origin": reflected_origin,
        "allows_null_origin": allows_null,
        "allows_credentials_wildcard": allows_credentials_wildcard,
        "misconfigured": misconfigured,
    }


def run(domain: str) -> dict[str, Any]:
    findings: list[str] = []
    risk = "low"

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{domain}"
        try:
            resp = fetch(base_url, method="HEAD", timeout=TIMEOUT)
            if resp.status_code < 500:
                break
        except Exception:
            continue
    else:
        return {
            "status": "error",
            "error": "Site unreachable",
            "misconfigured": False,
            "reflected_origin": False,
            "allows_null_origin": False,
            "allows_credentials_wildcard": False,
            "wildcard_no_credentials": False,
            "cors_tests": [],
            "risk": "low",
            "findings": [],
        }

    cors = _test_cors(base_url)

    # Check simple wildcard (without credentials — less severe but worth noting)
    wildcard_no_creds = any(
        t.get("wildcard") and not t.get("allow_credentials")
        for t in cors["tests"]
        if "error" not in t
    )

    if cors["allows_credentials_wildcard"]:
        findings.append("CORS: Access-Control-Allow-Origin: * with Allow-Credentials: true — credentials exposed to any origin (critical)")
        risk = "critical"
    if cors["reflected_origin"]:
        findings.append("CORS: Server reflects arbitrary Origin in Access-Control-Allow-Origin — cross-origin requests allowed from any domain")
        risk = "critical" if risk != "critical" else risk
    if cors["allows_null_origin"]:
        findings.append("CORS: Null origin allowed — can be exploited via sandboxed iframes")
        risk = max(risk, "high", key=lambda r: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(r, 0))
    if wildcard_no_creds and not cors["misconfigured"]:
        findings.append("CORS: Wildcard origin (*) — acceptable for public APIs but review if any sensitive data is returned")
        risk = max(risk, "medium", key=lambda r: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(r, 0))

    return {
        "status": "ok",
        "misconfigured": cors["misconfigured"],
        "reflected_origin": cors["reflected_origin"],
        "allows_null_origin": cors["allows_null_origin"],
        "allows_credentials_wildcard": cors["allows_credentials_wildcard"],
        "wildcard_no_credentials": wildcard_no_creds,
        "cors_tests": cors["tests"],
        "risk": risk,
        "findings": findings,
    }

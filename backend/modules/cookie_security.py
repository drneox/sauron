"""
Cookie Security Analysis Module
Inspects Set-Cookie headers for missing security flags
"""
import logging
from typing import Any

from modules.common import fetch

logger = logging.getLogger(__name__)

TIMEOUT = 10

SESSION_KEYWORDS = {"session", "sess", "sid", "auth", "token", "jwt", "login", "user", "account", "csrf", "xsrf"}


def _parse_set_cookie(header_value: str) -> dict:
    """Parse a Set-Cookie header string into a structured dict."""
    parts = [p.strip() for p in header_value.split(";")]
    name_value = parts[0]
    name = name_value.split("=")[0].strip()

    flags = {p.lower().split("=")[0].strip(): p.split("=", 1)[1].strip() if "=" in p else True
             for p in parts[1:]}

    return {
        "name": name,
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": flags.get("samesite") if isinstance(flags.get("samesite"), str) else None,
        "path": flags.get("path", "/") if isinstance(flags.get("path"), str) else "/",
        "domain": flags.get("domain") if isinstance(flags.get("domain"), str) else None,
        "raw": header_value,
    }


def run(domain: str) -> dict[str, Any]:
    findings: list[str] = []
    cookies: list[dict] = []
    risk = "low"

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = fetch(url, timeout=TIMEOUT)
            if resp.status_code < 500:
                # Collect Set-Cookie from all responses in redirect chain
                all_headers = list(resp.headers.get_list("set-cookie"))
                for r in resp.history:
                    all_headers += list(r.headers.get_list("set-cookie"))
                for raw in all_headers:
                    try:
                        cookies.append(_parse_set_cookie(raw))
                    except Exception:
                        pass
                break
        except Exception:
            continue

    if not cookies:
        return {
            "status": "ok",
            "cookies": [],
            "insecure_count": 0,
            "missing_httponly": [],
            "missing_secure": [],
            "missing_samesite": [],
            "session_cookies_insecure": [],
            "risk": "low",
            "findings": ["No cookies detected"],
        }

    missing_secure = []
    missing_httponly = []
    missing_samesite = []
    session_cookies_insecure = []

    is_https = domain and True  # assume HTTPS target

    for c in cookies:
        name_lower = c["name"].lower()
        is_session = any(kw in name_lower for kw in SESSION_KEYWORDS)

        if not c["secure"] and is_https:
            missing_secure.append(c["name"])
        if not c["httponly"]:
            missing_httponly.append(c["name"])
        if not c["samesite"]:
            missing_samesite.append(c["name"])
        elif c["samesite"].lower() == "none" and not c["secure"]:
            findings.append(f"Cookie '{c['name']}': SameSite=None requires Secure flag")

        if is_session and (not c["secure"] or not c["httponly"]):
            session_cookies_insecure.append(c["name"])

    if session_cookies_insecure:
        findings.append(f"Session/auth cookies missing security flags: {', '.join(session_cookies_insecure)}")
        risk = "high"
    if missing_secure:
        findings.append(f"Cookies without Secure flag (sent over HTTP too): {', '.join(missing_secure)}")
        risk = max(risk, "medium", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r,0))
    if missing_httponly:
        findings.append(f"Cookies without HttpOnly (accessible via JS/XSS): {', '.join(missing_httponly[:5])}")
        risk = max(risk, "medium", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r,0))
    if missing_samesite:
        findings.append(f"Cookies without SameSite flag (CSRF risk): {', '.join(missing_samesite[:5])}")
        risk = max(risk, "low", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r,0))

    insecure_count = len(set(missing_secure + missing_httponly + missing_samesite + session_cookies_insecure))

    return {
        "status": "ok",
        "cookies": cookies,
        "insecure_count": insecure_count,
        "missing_httponly": missing_httponly,
        "missing_secure": missing_secure,
        "missing_samesite": missing_samesite,
        "session_cookies_insecure": session_cookies_insecure,
        "risk": risk,
        "findings": findings,
    }

"""
HTTP Security Headers Analysis Module
Checks for presence and correctness of security headers
"""
import httpx
import logging
from typing import Any

from modules.common import SSRFBlocked, fetch

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "recommended": "max-age=31536000; includeSubDomains",
        "severity": "high",
    },
    "Content-Security-Policy": {
        "description": "Controls resources the browser is allowed to load",
        "recommended": "default-src 'self'",
        "severity": "high",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "medium",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "severity": "low",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated in modern browsers)",
        "recommended": "0 (rely on CSP instead)",
        "severity": "info",
    },
    "Cache-Control": {
        "description": "Controls caching behavior",
        "recommended": "no-store for sensitive pages",
        "severity": "low",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context",
        "recommended": "same-origin",
        "severity": "low",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource loads",
        "recommended": "same-origin",
        "severity": "low",
    },
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def run(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "ok",
        "url": None,
        "status_code": None,
        "headers_present": {},
        "headers_missing": [],
        "leaky_headers": {},
        "redirects_to_https": False,
        "risk": "low",
        "findings": [],
        "score": 0,
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            resp = fetch(
                url,
                timeout=10,
                headers={"User-Agent": "ASM-Scanner/1.0"},
            )
            result["url"] = str(resp.url)
            result["status_code"] = resp.status_code
            result["redirects_to_https"] = str(resp.url).startswith("https://")

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            present = {}
            missing = []
            for header, info in SECURITY_HEADERS.items():
                h_lower = header.lower()
                if h_lower in headers_lower:
                    present[header] = {
                        "value": headers_lower[h_lower],
                        "description": info["description"],
                    }
                else:
                    if info["severity"] != "info":
                        missing.append({
                            "header": header,
                            "description": info["description"],
                            "recommended": info["recommended"],
                            "severity": info["severity"],
                        })

            result["headers_present"] = present
            result["headers_missing"] = missing

            # Leaky headers
            for lh in LEAKY_HEADERS:
                if lh.lower() in headers_lower:
                    result["leaky_headers"][lh] = headers_lower[lh.lower()]
                    result["findings"].append(
                        f"Header '{lh}: {headers_lower[lh.lower()]}' reveals server technology"
                    )

            # Score (0-100)
            important = {"Strict-Transport-Security", "Content-Security-Policy",
                         "X-Frame-Options", "X-Content-Type-Options"}
            present_important = sum(1 for h in important if h in present)
            total_checked = len(SECURITY_HEADERS) - 1  # exclude X-XSS-Protection
            present_count = len(present)
            result["score"] = round((present_count / total_checked) * 100)

            # Risk based on missing critical headers
            high_missing = [m for m in missing if m["severity"] == "high"]
            if len(high_missing) >= 2:
                result["risk"] = "high"
                for m in high_missing:
                    result["findings"].append(f"Missing critical header: {m['header']}")
            elif len(high_missing) == 1:
                result["risk"] = "medium"
                result["findings"].append(f"Missing security header: {high_missing[0]['header']}")

            if not result["redirects_to_https"] and scheme == "http":
                result["findings"].append("Site does not redirect HTTP to HTTPS")
                if result["risk"] == "low":
                    result["risk"] = "medium"

            break  # success, no need to try http

        except (httpx.ConnectError, SSRFBlocked):
            continue
        except Exception as e:
            logger.error(f"[headers] {domain}: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            break

    return result

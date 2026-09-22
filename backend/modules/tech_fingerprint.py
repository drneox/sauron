"""
Technology Fingerprinting Module
Detects web technologies via HTTP headers, HTML meta tags, and cookies
"""
import httpx
import re
import logging
from typing import Any

from modules.common import SSRFBlocked, fetch

logger = logging.getLogger(__name__)

# Patterns: (technology_name, header_or_source, pattern)
TECH_PATTERNS = [
    # Servers
    ("Apache", "server", r"apache"),
    ("Nginx", "server", r"nginx"),
    ("IIS", "server", r"microsoft-iis"),
    ("LiteSpeed", "server", r"litespeed"),
    ("OpenResty", "server", r"openresty"),
    # Frameworks / Languages
    ("PHP", "x-powered-by", r"php"),
    ("ASP.NET", "x-powered-by", r"asp\.net"),
    ("Express.js", "x-powered-by", r"express"),
    ("Ruby on Rails", "x-powered-by", r"phusion passenger"),
    # CDNs / Proxies
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("Fastly", "via", r"fastly"),
    ("Varnish", "via", r"varnish"),
    ("AWS CloudFront", "via", r"cloudfront"),
    # Security
    ("reCAPTCHA", "html", r"recaptcha"),
    ("hCaptcha", "html", r"hcaptcha"),
    # CMS
    ("WordPress", "html", r"wp-content|wp-includes"),
    ("WordPress", "link", r"wordpress"),
    ("Drupal", "x-generator", r"drupal"),
    ("Joomla", "html", r"joomla"),
    ("Ghost", "html", r"ghost\.org"),
    ("Shopify", "html", r"cdn\.shopify\.com"),
    ("Magento", "html", r"magento"),
    ("Wix", "html", r"wix\.com"),
    ("Squarespace", "html", r"squarespace"),
    # JS Frameworks
    ("React", "html", r"react|__REACT|_reactRootContainer"),
    ("Vue.js", "html", r"vue\.js|__vue__"),
    ("Angular", "html", r"ng-version|angular"),
    ("Next.js", "x-powered-by", r"next\.js"),
    ("Nuxt.js", "html", r"__NUXT__"),
    # Analytics
    ("Google Analytics", "html", r"google-analytics\.com|gtag\(|UA-\d+"),
    ("Google Tag Manager", "html", r"googletagmanager\.com"),
    ("Facebook Pixel", "html", r"connect\.facebook\.net"),
    # Misc
    ("jQuery", "html", r"jquery"),
    ("Bootstrap", "html", r"bootstrap"),
    ("Font Awesome", "html", r"font-awesome|fontawesome"),
]


def run(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "ok",
        "technologies": [],
        "server": None,
        "powered_by": None,
        "cookies": [],
        "risk": "low",
        "findings": [],
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            resp = fetch(
                url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
            )
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            html = resp.text[:50000]  # limit to first 50KB

            result["server"] = resp.headers.get("Server") or resp.headers.get("server")
            result["powered_by"] = resp.headers.get("X-Powered-By") or resp.headers.get("x-powered-by")

            # Cookies analysis
            for cookie in resp.cookies.jar:
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite"),
                }
                result["cookies"].append(cookie_info)
                if not cookie.secure:
                    result["findings"].append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie_info["httponly"]:
                    result["findings"].append(f"Cookie '{cookie.name}' missing HttpOnly flag")

            # Technology detection
            detected = set()
            for tech, source, pattern in TECH_PATTERNS:
                if source == "html":
                    text = html.lower()
                elif source in headers_lower:
                    text = headers_lower[source]
                else:
                    text = ""
                if text and re.search(pattern, text, re.IGNORECASE):
                    detected.add(tech)

            result["technologies"] = sorted(detected)

            # Risk: exposing server version
            server = result["server"] or ""
            if re.search(r"\d+\.\d+", server):
                result["findings"].append(
                    f"Server header reveals version: '{server}' — could aid targeted attacks"
                )
                result["risk"] = "medium"

            if result["powered_by"]:
                result["findings"].append(
                    f"X-Powered-By header reveals: '{result['powered_by']}'"
                )
                if result["risk"] == "low":
                    result["risk"] = "low"  # informational

            break

        except (httpx.ConnectError, SSRFBlocked):
            continue
        except Exception as e:
            logger.error(f"[tech] {domain}: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            break

    return result

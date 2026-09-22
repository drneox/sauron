"""
Robots.txt & Sitemap Analysis Module
Extracts hidden paths from robots.txt and sitemap.xml
"""
import re
import logging
from xml.etree import ElementTree
from typing import Any
from urllib.parse import urljoin

from modules.common import fetch

logger = logging.getLogger(__name__)

TIMEOUT = 10

SENSITIVE_PATH_PATTERNS = re.compile(
    r"(?i)(admin|login|secret|backup|private|config|api|upload|dashboard|internal|"
    r"staging|dev|test|debug|phpmy|wp-admin|\.env|\.git|database|passwd|shadow|"
    r"credentials|auth|token|jwt|key|cert|pem|\.sql|dump|\.bak|\.old|temp|tmp)",
)


def _fetch(url: str) -> tuple[int, str]:
    try:
        r = fetch(url, timeout=TIMEOUT,
                  headers={"User-Agent": "Mozilla/5.0 (compatible; DumbAuditor/1.0)"})
        return r.status_code, r.text
    except Exception:
        return 0, ""


def _parse_robots(content: str, base_url: str) -> dict:
    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []
    current_agent = "*"
    sensitive: list[str] = []

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        low = line.lower()
        if low.startswith("user-agent:"):
            current_agent = line.split(":", 1)[1].strip()
        elif low.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
                if SENSITIVE_PATH_PATTERNS.search(path):
                    sensitive.append(path)
        elif low.startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                allowed.append(path)
        elif low.startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)

    return {
        "disallowed": disallowed[:100],
        "allowed": allowed[:50],
        "sitemaps": sitemaps,
        "sensitive_paths": sensitive,
    }


def _parse_sitemap(content: str, base_url: str) -> list[str]:
    urls = []
    try:
        # Strip namespace for easier parsing
        content_clean = re.sub(r'\s+xmlns[^=]*="[^"]*"', '', content)
        root = ElementTree.fromstring(content_clean)
        for elem in root.iter():
            tag = elem.tag.lower().split("}")[-1]
            if tag == "loc" and elem.text:
                urls.append(elem.text.strip())
            elif tag == "sitemap" and elem.text:
                urls.append(elem.text.strip())
    except Exception:
        # Fallback regex
        urls = re.findall(r'<loc>([^<]+)</loc>', content)
    return urls[:500]


def run(domain: str) -> dict[str, Any]:
    findings: list[str] = []
    risk = "low"

    base_url = f"https://{domain}"
    # Check if HTTPS available, fallback to HTTP
    status, _ = _fetch(base_url)
    if status == 0:
        base_url = f"http://{domain}"

    # robots.txt
    robots_status, robots_content = _fetch(f"{base_url}/robots.txt")
    has_robots = robots_status == 200 and len(robots_content) > 10

    robots_data: dict = {}
    sitemap_urls_from_robots: list[str] = []

    if has_robots:
        robots_data = _parse_robots(robots_content, base_url)
        sitemap_urls_from_robots = robots_data.get("sitemaps", [])

        if robots_data.get("sensitive_paths"):
            findings.append(
                f"robots.txt discloses {len(robots_data['sensitive_paths'])} sensitive path(s): "
                + ", ".join(robots_data["sensitive_paths"][:5])
            )
            risk = "medium"

    # Sitemap
    sitemap_urls_to_try = sitemap_urls_from_robots or [
        f"{base_url}/sitemap.xml",
        f"{base_url}/sitemap_index.xml",
        f"{base_url}/sitemap.xml.gz",
    ]

    all_sitemap_entries: list[str] = []
    sitemap_found = False

    for sm_url in sitemap_urls_to_try[:3]:
        sm_status, sm_content = _fetch(sm_url)
        if sm_status == 200 and sm_content:
            sitemap_found = True
            entries = _parse_sitemap(sm_content, base_url)
            all_sitemap_entries.extend(entries)

    # Look for sensitive URLs in sitemap
    sensitive_sitemap = [u for u in all_sitemap_entries if SENSITIVE_PATH_PATTERNS.search(u)]

    if sensitive_sitemap:
        findings.append(f"Sitemap exposes {len(sensitive_sitemap)} sensitive URL(s)")
        risk = max(risk, "medium", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r,0))

    # "No robots.txt found" is deliberately NOT a finding: a missing robots.txt
    # is neutral inventory, not a problem (robots_found already reports it).

    return {
        "status": "ok",
        "robots_found": has_robots,
        "robots_disallowed": robots_data.get("disallowed", []),
        "robots_allowed": robots_data.get("allowed", []),
        "robots_sitemaps": sitemap_urls_from_robots,
        "sensitive_in_robots": robots_data.get("sensitive_paths", []),
        "sitemap_found": sitemap_found,
        "sitemap_url_count": len(all_sitemap_entries),
        "sitemap_urls_sample": all_sitemap_entries[:20],
        "sensitive_in_sitemap": sensitive_sitemap[:20],
        "risk": risk,
        "findings": findings,
    }

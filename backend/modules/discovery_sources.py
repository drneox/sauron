"""
Discovery Sources Aggregator
Passive multi-source host discovery. Each source is async, fault-tolerant
(never raises — returns an empty set on failure) and logs degraded sources.

Sources without API key (always enabled):
  - crt.sh        (certificate transparency)
  - certspotter   (certificate transparency, own rate limit — 429 tolerated)
  - wayback       (web.archive.org CDX API)
  - grep.app      (public code search — hostnames in snippets)

Key-gated sources (skipped silently unless the env var is set):
  - securitytrails (SECURITYTRAILS_API_KEY)
  - otx            (OTX_API_KEY — AlienVault Open Threat Exchange)

Public code/API-doc surface (used by modules.api_exposure):
  - github_repo_search  (repo search, no key needed; GITHUB_TOKEN raises limits)
  - github_code_search  (code search, requires GITHUB_TOKEN)
  - postman_search      (Postman Public API Network, internal search proxy,
                         no auth — verified working 2026-09)
"""
import asyncio
import html
import logging
import os
import re
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (compatible; DumbAuditor/1.0)"
DEFAULT_TIMEOUT = 25

_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _host_of(url_or_host: str) -> str | None:
    """Extract a lowercase hostname from a URL or bare host string."""
    text = url_or_host.strip()
    if not text:
        return None
    if "://" not in text:
        text = "http://" + text
    try:
        host = urlparse(text).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _matches_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


async def crtsh_subs(domain: str) -> set[str]:
    """Certificate transparency via crt.sh (moved from subdomain_enum)."""
    subdomains: set[str] = set()
    for attempt in range(2):  # retry once on failure
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": USER_AGENT},
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower().lstrip("*.")
                            if _matches_domain(sub, domain):
                                subdomains.add(sub)
                    break  # success
                logger.debug(f"[crtsh] {domain}: HTTP {resp.status_code}")
        except Exception as e:
            logger.debug(f"[crtsh] attempt {attempt + 1} for {domain}: {e}")
            if attempt == 0:
                await asyncio.sleep(1)
    if not subdomains:
        logger.info(f"[crtsh] no results for {domain} (source down or empty)")
    return subdomains


async def certspotter_subs(domain: str) -> set[str]:
    """Certificate transparency via CertSpotter (free, no key, own rate limit)."""
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code == 429:
                logger.info(f"[certspotter] rate limited (429) for {domain} — skipping")
                return subdomains
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if _matches_domain(name, domain):
                            subdomains.add(name)
            else:
                logger.debug(f"[certspotter] {domain}: HTTP {resp.status_code}")
    except Exception as e:
        logger.debug(f"[certspotter] {domain}: {e}")
    if not subdomains:
        logger.info(f"[certspotter] no results for {domain} (source down or empty)")
    return subdomains


async def wayback_subs(domain: str) -> set[str]:
    """Hostnames seen by the Internet Archive Wayback Machine (CDX API).

    The wildcard CDX query is slow to start streaming (30s+ under load),
    so this source deviates from the default timeout: a single 60s attempt."""
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "10000",
                },
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code == 200:
                rows = resp.json()
                for row in rows[1:]:  # first row is the header ["original"]
                    if not row:
                        continue
                    host = _host_of(row[0])
                    if host and _matches_domain(host, domain):
                        subdomains.add(host)
            else:
                logger.debug(f"[wayback] {domain}: HTTP {resp.status_code}")
    except Exception as e:
        logger.debug(f"[wayback] {domain}: {e}")
    if not subdomains:
        logger.info(f"[wayback] no results for {domain} (source down or empty)")
    return subdomains


async def grepapp_hosts(query: str) -> set[str]:
    """Hostnames mentioned in public code, via grep.app search.

    Works for both brand discovery (query = company/brand name) and apex
    subdomain discovery (query = apex domain). Snippets are HTML-escaped
    with <mark> tags around matches — unescape and strip tags first.
    Caller is responsible for filtering the returned hosts by brand/domain.
    """
    hosts: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(
                "https://grep.app/api/search",
                params={"q": query},
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code == 429:
                logger.info(f"[grepapp] rate limited (429) for '{query}' — skipping")
                return hosts
            if resp.status_code != 200:
                logger.debug(f"[grepapp] '{query}': HTTP {resp.status_code}")
                return hosts
            data = resp.json()
            for hit in (data.get("hits") or {}).get("hits") or []:
                snippet = ((hit.get("content") or {}).get("snippet")) or ""
                # Strip tags inline (no space): grep.app wraps matches in
                # <mark> tags that can sit in the middle of a hostname.
                text = _HTML_TAG_RE.sub("", html.unescape(snippet))
                for match in _HOST_RE.findall(text):
                    hosts.add(match.lower().rstrip("."))
    except Exception as e:
        logger.debug(f"[grepapp] '{query}': {e}")
    if not hosts:
        logger.info(f"[grepapp] no results for '{query}' (source down or empty)")
    return hosts


async def securitytrails_subs(domain: str) -> set[str]:
    """SecurityTrails subdomain API — requires SECURITYTRAILS_API_KEY.
    Skipped silently (empty set) when the key is not configured."""
    api_key = os.getenv("SECURITYTRAILS_API_KEY")
    if not api_key:
        return set()
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers={"APIKEY": api_key, "User-Agent": USER_AGENT},
            )
            if resp.status_code == 200:
                for sub in (resp.json().get("subdomains") or []):
                    host = f"{sub.strip().lower()}.{domain}"
                    subdomains.add(host)
            else:
                logger.debug(f"[securitytrails] {domain}: HTTP {resp.status_code}")
    except Exception as e:
        logger.debug(f"[securitytrails] {domain}: {e}")
    return subdomains


async def otx_subs(domain: str) -> set[str]:
    """AlienVault OTX passive DNS — requires OTX_API_KEY.
    Skipped silently (empty set) when the key is not configured."""
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return set()
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers={"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT},
            )
            if resp.status_code == 200:
                for record in (resp.json().get("passive_dns") or []):
                    host = (record.get("hostname") or "").strip().lower()
                    if _matches_domain(host, domain):
                        subdomains.add(host)
            else:
                logger.debug(f"[otx] {domain}: HTTP {resp.status_code}")
    except Exception as e:
        logger.debug(f"[otx] {domain}: {e}")
    return subdomains



_GITHUB_API = "https://api.github.com"
_GITHUB_REPO_CAP = 10
_GITHUB_CODE_CAP = 20
_POSTMAN_CAP = 10

_POSTMAN_PROXY_URL = "https://www.postman.com/_api/ws/proxy"


def _github_headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,  # GitHub API rejects requests without one
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def github_repo_search(query: str, domain: str) -> list[dict]:
    """GitHub repository search for a brand/domain — no auth required.

    Uses GITHUB_TOKEN when present (raises the unauthenticated 10 req/min
    search limit). 403/429 (rate limit) is tolerated: returns an empty list.
    Results are ranked by relevance: brand in the repo name beats the domain
    appearing in the description; stars break ties. Capped at 10.
    """
    token = os.getenv("GITHUB_TOKEN")
    brand = query.lower()
    repos: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{_GITHUB_API}/search/repositories",
                params={"q": query, "sort": "stars", "order": "desc"},
                headers=_github_headers(token),
            )
            if resp.status_code in (403, 429):
                logger.info(f"[github] rate limited ({resp.status_code}) for '{query}' — skipping")
                return repos
            if resp.status_code != 200:
                logger.debug(f"[github] repo search '{query}': HTTP {resp.status_code}")
                return repos
            for item in (resp.json().get("items") or []):
                full_name = item.get("full_name") or ""
                description = item.get("description") or ""
                name_hit = brand in full_name.lower()
                desc_hit = domain.lower() in description.lower()
                if not (name_hit or desc_hit):
                    continue
                repos.append({
                    "name":        full_name,
                    "url":         item.get("html_url") or "",
                    "description": description,
                    "stars":       item.get("stargazers_count") or 0,
                    "_score":      (2 if name_hit else 0) + (1 if desc_hit else 0),
                })
    except Exception as e:
        logger.debug(f"[github] repo search '{query}': {e}")
        return repos
    repos.sort(key=lambda r: (r["_score"], r["stars"]), reverse=True)
    for r in repos:
        del r["_score"]
    return repos[:_GITHUB_REPO_CAP]


async def github_code_search(domain: str) -> list[dict]:
    """GitHub code search for files mentioning the domain — requires GITHUB_TOKEN.

    The code search API rejects unauthenticated requests entirely, so this
    source is skipped silently (empty list) when the token is not configured.
    Capped at 20 hits; each hit carries the file URL, repo and path.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return []
    hits: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{_GITHUB_API}/search/code",
                params={"q": f"{domain} in:file"},
                headers=_github_headers(token),
            )
            if resp.status_code in (403, 429):
                logger.info(f"[github] code search rate limited ({resp.status_code}) for '{domain}' — skipping")
                return hits
            if resp.status_code != 200:
                logger.debug(f"[github] code search '{domain}': HTTP {resp.status_code}")
                return hits
            for item in (resp.json().get("items") or [])[:_GITHUB_CODE_CAP]:
                hits.append({
                    "url":  item.get("html_url") or "",
                    "repo": (item.get("repository") or {}).get("full_name") or "",
                    "path": item.get("path") or "",
                })
    except Exception as e:
        logger.debug(f"[github] code search '{domain}': {e}")
    return hits


async def postman_search(query: str) -> dict:
    """Postman Public API Network keyword search — no auth required.

    Uses the internal search proxy the postman.com/explore web app calls
    (POST /_api/ws/proxy, service "search", path "/search-all"); verified
    working without any token. Returns {"collections": [...], "workspaces":
    [...]} with public URLs, both capped at 10. Empty dicts on failure.
    If Postman ever gates this endpoint, callers should degrade to the
    documented stub {"checked": false, "note": "not accessible without API key"}.
    """
    out: dict = {"collections": [], "workspaces": []}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.post(
                _POSTMAN_PROXY_URL,
                json={
                    "service": "search",
                    "method": "POST",
                    "path": "/search-all",
                    "body": {"queryText": query},
                },
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code != 200:
                logger.debug(f"[postman] '{query}': HTTP {resp.status_code}")
                return out
            data = resp.json().get("data") or {}
            for hit in (data.get("collection") or [])[:_POSTMAN_CAP]:
                doc = hit.get("document") or {}
                handle = doc.get("publisherHandle") or ""
                cid = doc.get("id") or ""
                if not (handle and cid):
                    continue
                out["collections"].append({
                    "name":      doc.get("name") or "",
                    "url":       f"https://www.postman.com/{handle}/collection/{cid}",
                    "publisher": doc.get("publisherName") or "",
                    "description": doc.get("description") or doc.get("summary") or "",
                })
            for hit in (data.get("workspace") or [])[:_POSTMAN_CAP]:
                doc = hit.get("document") or {}
                handle = doc.get("publisherHandle") or ""
                slug = doc.get("slug") or ""
                if not (handle and slug):
                    continue
                out["workspaces"].append({
                    "name":      doc.get("name") or "",
                    "url":       f"https://www.postman.com/{handle}/workspace/{slug}",
                    "publisher": doc.get("publisherName") or "",
                    "collections": doc.get("collectionCount") or 0,
                })
    except Exception as e:
        logger.debug(f"[postman] '{query}': {e}")
    return out

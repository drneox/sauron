"""
JavaScript Secrets Scanner Module
Crawls JS files linked from the homepage and scans for hardcoded secrets.
If the katana binary is installed (and tools_katana is on), a shallow crawl
feeds extra JS files into the scan and its discovered paths into `endpoints`
with source "katana".
"""
import asyncio
import httpx
import re
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from modules import tools_runner
from modules.common import fetch, make_client

logger = logging.getLogger(__name__)

TIMEOUT = 10
MAX_JS_FILES = 20
MAX_JS_SIZE = 500_000  # 500 KB
MAX_MAP_SIZE = 2_000_000  # 2 MB
MAX_ENDPOINTS = 50
MAX_HOSTS = 50
MAX_GUIDS = 20
MAX_CANDIDATE_KEYS = 20

# JS mining patterns
ENDPOINT_RE = re.compile(
    r"""["'](/api/[^"'\s]*|/v[1-9]/[^"'\s]*|/oauth/[^"'\s]*|/graphql[^"'\s]*|api/[^"'\s]+)["']"""
)
URL_PATH_RE = re.compile(
    r"""https?://[a-zA-Z0-9.\-]+(?::\d+)?(/api/[^"'\s]*|/v[1-9]/[^"'\s]*|/oauth/[^"'\s]*|/graphql[^"'\s]*)"""
)
ABS_URL_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9])(?::\d+)?")
GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
JWT_FULL_RE = re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+")

CLOUD_HOST_MARKERS = (
    "azure-api.net", "azurewebsites.net", "amazonaws.com", "cloudfront.net",
    "firebaseio.com", "blob.core.windows.net", "herokuapp.com", "azurefd.net",
    "trafficmanager.net", "cloudapp.azure.com", "googleapis.com", "workers.dev",
)
INTERNAL_ENV_KEYWORDS = ("dev", "desa", "test", "stg", "staging", "qa", "cert", "uat", "sandbox")

# (keyword found near a long secret-looking string, candidate type) — most specific first
KEY_CONTEXT_KEYWORDS = [
    ("ocp-apim-subscription-key", "APIM Subscription Key candidate"),
    ("subscription-key", "APIM Subscription Key candidate"),
    ("subscriptionkey", "APIM Subscription Key candidate"),
    ("apim", "APIM Subscription Key candidate"),
    ("x-api-key", "API Key candidate"),
    ("api-key", "API Key candidate"),
    ("apikey", "API Key candidate"),
]
_QUOTED_VALUE_RE = re.compile(r"""["']([0-9a-fA-F]{32,}|[A-Za-z0-9][A-Za-z0-9_\-]{31,127})["']""")

# (label, pattern, severity)
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}",                                         "critical"),
    ("AWS Secret Key",      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]",  "critical"),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}",                                   "critical"),
    ("Firebase",            r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",                  "critical"),
    ("GitHub Token",        r"ghp_[0-9a-zA-Z]{36}",                                       "critical"),
    ("GitHub OAuth",        r"gho_[0-9a-zA-Z]{36}",                                       "critical"),
    ("Slack Token",         r"xox[baprs]-[0-9a-zA-Z]{10,48}",                             "high"),
    ("Slack Webhook",       r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[a-zA-Z0-9]+", "high"),
    ("Stripe Secret",       r"sk_live_[0-9a-zA-Z]{24,}",                                  "critical"),
    ("Stripe Publishable",  r"pk_live_[0-9a-zA-Z]{24,}",                                  "medium"),
    ("Stripe Test",         r"sk_test_[0-9a-zA-Z]{24,}",                                  "low"),
    ("SendGrid",            r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",               "high"),
    ("Mailchimp",           r"[0-9a-f]{32}-us[0-9]{1,2}",                                 "medium"),
    ("Twilio",              r"SK[0-9a-fA-F]{32}",                                          "high"),
    ("OpenAI Key",          r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",                "high"),
    ("OpenAI Key (new)",    r"sk-proj-[a-zA-Z0-9\-_]{50,}",                               "high"),
    ("JWT Token",           r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "medium"),
    ("Private Key",         r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY",                  "critical"),
    ("Basic Auth in URL",   r"https?://[^@\s]+:[^@\s]+@[^\s/]+",                          "high"),
    ("Generic Secret",      r"(?i)(?:secret|password|passwd|api_key|apikey|access_token)['\"\s]*[:=]['\"\s]*['\"][a-zA-Z0-9\-_]{8,}['\"]", "medium"),
]

_COMPILED = [(label, re.compile(pat), sev) for label, pat, sev in SECRET_PATTERNS]


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    urls = []
    for src in srcs:
        if src.startswith("data:") or src.startswith("//"):
            src = "https:" + src if src.startswith("//") else src
        full = urljoin(base_url, src)
        parsed = urlparse(full)
        if parsed.netloc and ".js" in parsed.path:
            urls.append(full)
    return list(dict.fromkeys(urls))[:MAX_JS_FILES]


def _scan_js(content: str, source_url: str) -> list[dict]:
    hits = []
    seen = set()
    for label, pattern, severity in _COMPILED:
        for match in pattern.finditer(content):
            val = match.group(0)[:80]
            key = (label, val[:20])
            if key in seen:
                continue
            seen.add(key)
            line_no = content[:match.start()].count("\n") + 1
            # Redact the actual value for display; the full value rides along as
            # `value` so the report UI can reveal it on demand (eye toggle).
            redacted = val[:6] + "***" + val[-3:] if len(val) > 12 else "***"
            hits.append({
                "type": label,
                "severity": severity,
                "file": source_url,
                "line": line_no,
                "snippet": redacted,
                "value": val,
            })
    return hits


def _extract_endpoints(content: str, source_url: str, seen: set, out: list) -> None:
    for pattern in (ENDPOINT_RE, URL_PATH_RE):
        for m in pattern.finditer(content):
            path = m.group(1).rstrip(".,;)")
            if path in seen or len(out) >= MAX_ENDPOINTS:
                continue
            seen.add(path)
            out.append({"endpoint": path, "source": source_url})


def _classify_host(host: str, base_domain: str) -> str:
    host_l = host.lower()
    tokens = re.split(r"[.\-]", host_l)
    for tok in tokens:
        for kw in INTERNAL_ENV_KEYWORDS:
            if (tok == kw) if len(kw) <= 2 else tok.startswith(kw):
                return "internal-env"
    if host_l == base_domain or host_l.endswith("." + base_domain):
        return "subdomain"
    if any(marker in host_l for marker in CLOUD_HOST_MARKERS):
        return "cloud"
    return "third-party"


def _extract_hosts(content: str, base_domain: str, source_url: str, seen: set, out: list) -> None:
    for m in ABS_URL_RE.finditer(content):
        host = m.group(1).lower()
        if host in seen or len(out) >= MAX_HOSTS:
            continue
        seen.add(host)
        out.append({"host": host, "kind": _classify_host(host, base_domain), "source": source_url})


def _extract_guids(content: str, source_url: str, seen: set, out: list) -> None:
    for m in GUID_RE.finditer(content):
        guid = m.group(0)
        if guid in seen or len(out) >= MAX_GUIDS:
            continue
        seen.add(guid)
        window = content[max(0, m.start() - 100):m.end() + 100].lower()
        if "tenant" in window:
            ctx = "tenant-id"
        elif "client" in window:
            ctx = "client-id"
        elif "subscription" in window:
            ctx = "subscription-id"
        else:
            ctx = "generic"
        out.append({"guid": guid, "context": ctx, "source": source_url})


def _extract_candidate_keys(content: str, source_url: str, seen: set, out: list) -> None:
    """Long secret-looking strings appearing near API-key-related keywords.
    Values are kept COMPLETE here — they only leave the module via the `_raw`
    handoff key, never through the public result."""
    lower = content.lower()
    for keyword, ktype in KEY_CONTEXT_KEYWORDS:
        start = 0
        while len(out) < MAX_CANDIDATE_KEYS:
            idx = lower.find(keyword, start)
            if idx == -1:
                break
            start = idx + len(keyword)
            win_start = max(0, idx - 200)
            window = content[win_start: idx + len(keyword) + 200]
            for vm in _QUOTED_VALUE_RE.finditer(window):
                val = vm.group(1)
                if val in seen or len(out) >= MAX_CANDIDATE_KEYS:
                    continue
                seen.add(val)
                line_no = content.count("\n", 0, win_start + vm.start()) + 1
                out.append({"type": ktype, "value": val, "source": source_url, "line": line_no})


def _probe_sourcemap(client: httpx.Client, js_url: str) -> dict | None:
    map_url = js_url + ".map"
    try:
        r = fetch(map_url, client=client, max_bytes=MAX_MAP_SIZE + 1)
        if r.status_code != 200 or len(r.content) >= MAX_MAP_SIZE:
            return None
        data = r.json()
        if isinstance(data, dict) and data.get("sourcesContent"):
            return {"js": js_url, "map": map_url, "has_sources_content": True}
    except Exception:
        pass
    return None


def run(domain: str) -> dict[str, Any]:
    findings_list: list[str] = []
    secrets: list[dict] = []
    js_files_scanned: list[str] = []
    risk = "low"

    base_url = f"https://{domain}"
    try:
        resp = fetch(base_url, timeout=TIMEOUT)
        if resp.status_code >= 400:
            base_url = f"http://{domain}"
            resp = fetch(base_url, timeout=TIMEOUT)
    except Exception:
        try:
            base_url = f"http://{domain}"
            resp = fetch(base_url, timeout=TIMEOUT)
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "js_files_scanned": [],
                "secrets_found": [],
                "secret_count": 0,
                "by_severity": {},
                "endpoints": [],
                "hosts": [],
                "guids": [],
                "sourcemaps": [],
                "risk": "low",
                "findings": [],
            }

    # Also scan inline scripts
    inline_hits = _scan_js(resp.text, base_url + " (inline)")
    secrets.extend(inline_hits)
    contents: list[tuple[str, str]] = [(resp.text, base_url + " (inline)")]

    js_urls = _extract_js_urls(resp.text, str(resp.url))
    sourcemaps: list[dict] = []

    # katana crawl: extra JS files to scan + discovered paths for `endpoints`
    katana_paths: list[str] = []
    if tools_runner.tool_enabled("katana") and tools_runner.which_tool("katana"):
        try:
            kr = asyncio.run(tools_runner.katana_crawl(domain))
            if kr.get("status") == "ok":
                for u in kr.get("js") or []:
                    if u not in js_urls and len(js_urls) < MAX_JS_FILES:
                        js_urls.append(u)
                for u in kr.get("urls") or []:
                    path = urlparse(u).path
                    if path and path != "/" and path not in katana_paths:
                        katana_paths.append(path)
        except Exception as e:
            logger.debug(f"[js_secrets] katana crawl failed for {domain}: {e}")

    with make_client(timeout=TIMEOUT) as client:
        for url in js_urls:
            try:
                r = fetch(url, client=client, max_bytes=MAX_JS_SIZE + 1)
                if r.status_code == 200 and len(r.content) < MAX_JS_SIZE:
                    hits = _scan_js(r.text, url)
                    secrets.extend(hits)
                    js_files_scanned.append(url)
                    contents.append((r.text, url))
                    sm = _probe_sourcemap(client, url)
                    if sm:
                        sourcemaps.append(sm)
            except Exception:
                pass

    # ── JS mining: endpoints, hosts, GUIDs, candidate keys ─────────────────────
    base_domain = ".".join(domain.split(".")[-2:])
    seen_ep: set = set()
    seen_h: set = set()
    seen_g: set = set()
    seen_k: set = set()
    endpoints: list[dict] = []
    hosts: list[dict] = []
    guids: list[dict] = []
    candidates: list[dict] = []
    for text, src in contents:
        _extract_endpoints(text, src, seen_ep, endpoints)
        _extract_hosts(text, base_domain, src, seen_h, hosts)
        _extract_guids(text, src, seen_g, guids)
        _extract_candidate_keys(text, src, seen_k, candidates)
        for m in JWT_FULL_RE.finditer(text):
            tok = m.group(0)
            if tok not in seen_k:
                seen_k.add(tok)
                candidates.append({"type": "JWT Token", "value": tok, "source": src, "line": 0})

    # katana-discovered paths join the endpoint inventory under source "katana"
    for path in katana_paths:
        if path in seen_ep or len(endpoints) >= MAX_ENDPOINTS:
            continue
        seen_ep.add(path)
        endpoints.append({"path": path, "source": "katana"})

    cloud_hosts = [h["host"] for h in hosts if h["kind"] == "cloud"]
    internal_hosts = [h["host"] for h in hosts if h["kind"] == "internal-env"]
    key_candidates = [c for c in candidates if c["type"] != "JWT Token"]

    # Candidate keys appear in the public result redacted, like any other secret
    for c in key_candidates:
        val = c["value"]
        secrets.append({
            "type": c["type"],
            "severity": "high",
            "file": c["source"],
            "line": c["line"],
            "snippet": val[:6] + "***" + val[-3:] if len(val) > 12 else "***",
            "value": val,
        })

    # Deduplicate
    seen = set()
    deduped = []
    for s in secrets:
        key = (s["type"], s["snippet"], s["file"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)

    by_severity: dict[str, list] = {}
    for s in deduped:
        by_severity.setdefault(s["severity"], []).append(s)

    if by_severity.get("critical"):
        findings_list.append(f"{len(by_severity['critical'])} critical secret(s) found in JS files (API keys, credentials)")
        risk = "critical"
    if by_severity.get("high"):
        findings_list.append(f"{len(by_severity['high'])} high-severity secret(s) found in JS files")
        risk = risk if risk == "critical" else "high"
    if by_severity.get("medium"):
        findings_list.append(f"{len(by_severity['medium'])} potential secret(s) (medium) found in JS files")
        risk = risk if risk in ("critical", "high") else "medium"

    if endpoints or cloud_hosts:
        findings_list.append(f"JS bundle exposes {len(endpoints)} API endpoints and {len(cloud_hosts)} cloud gateway hosts")
    for sm in sourcemaps:
        if sm.get("has_sources_content"):
            findings_list.append(f"Source map with full source code exposed: {sm['map']}")
    if internal_hosts:
        findings_list.append(f"References to non-production environments found in JS ({', '.join(internal_hosts[:3])})")
    if key_candidates:
        findings_list.append(f"{len(key_candidates)} candidate API keys found near APIM-related keywords")

    if (any(sm.get("has_sources_content") for sm in sourcemaps) or key_candidates) and risk != "critical":
        risk = "high"

    # Internal handoff for secret_verification — the orchestrator pops `_raw`
    # before persisting, so full key values never reach the API response.
    raw = {
        "candidate_keys": [
            {"type": c["type"], "value": c["value"], "host_hints": cloud_hosts, "source": c["source"]}
            for c in candidates
        ],
        "endpoints": endpoints,
        "hosts": hosts,
    }

    return {
        "status": "ok",
        "js_files_scanned": js_files_scanned,
        "secrets_found": deduped,
        "secret_count": len(deduped),
        "by_severity": {k: len(v) for k, v in by_severity.items()},
        "endpoints": endpoints,
        "hosts": hosts,
        "guids": guids,
        "sourcemaps": sourcemaps,
        "risk": risk,
        "findings": findings_list,
        "_raw": raw,
    }

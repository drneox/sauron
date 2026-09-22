"""
frontend_cve.py — Frontend library detection + vulnerability lookup.

Uses the retire.js jsrepository.json as fingerprint + vulnerability database.
https://github.com/RetireJS/retire.js

Detection pipeline:
  1. Fetch homepage (SSL-permissive, www. fallback, HTTP fallback)
  2. Extract all <script src> and <link href> URLs
  3. Apply retire.js uri/filename extractors against all URLs   → versioned hits
  4. Fetch JS file content (16 KB range) for unversioned libs
  5. Apply retire.js filecontent extractors against banner content → versioned hits
  6. Framework/bundler heuristics (ASP.NET, Next.js, etc.)       → unversioned hints
  7. Match detected versions against retire.js vulnerability DB
  8. Return structured result (same schema consumed by TechSection.tsx + PDF)
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from packaging.version import InvalidVersion, Version

from modules.common import afetch, make_async_client

# ── Configuration ──────────────────────────────────────────────────────────────
TIMEOUT     = httpx.Timeout(15.0, connect=8.0)
CONCURRENCY = 8
BANNER_SIZE = 32_768          # bytes per JS file fetch (32 KB covers minified lib init blocks)
CACHE_TTL   = 86_400          # 24 h retire.js DB cache

_RETIREJS_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/"
    "repository/jsrepository.json"
)
_CACHE_PATH = Path(__file__).parent / "data" / "retirejs_cache.json"

# ── SSL helpers ────────────────────────────────────────────────────────────────

def _permissive_ssl_ctx() -> ssl.SSLContext:
    """TLS context that accepts legacy ciphers and old protocol versions."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except AttributeError:
        pass
    return ctx


# ── retire.js DB ───────────────────────────────────────────────────────────────

def _load_cached_db() -> dict | None:
    if not _CACHE_PATH.exists():
        return None
    try:
        if time.time() - _CACHE_PATH.stat().st_mtime > CACHE_TTL:
            return None
        return json.loads(_CACHE_PATH.read_text())
    except Exception:
        return None


async def _fetch_retirejs_db() -> dict:
    cached = _load_cached_db()
    if cached:
        return cached
    async with make_async_client(timeout=30) as c:
        r = await afetch(_RETIREJS_URL, client=c, max_bytes=50_000_000)
        r.raise_for_status()
        data = r.json()
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(json.dumps(data))
    return data


# ── Version range matching ─────────────────────────────────────────────────────

def _ver_satisfies(version_str: str, vuln: dict) -> bool:
    """Return True if version_str falls within retire.js vulnerability range."""
    try:
        v = Version(version_str)
    except InvalidVersion:
        return False
    try:
        if "atOrAbove" in vuln and v < Version(vuln["atOrAbove"]):
            return False
        if "above" in vuln and v <= Version(vuln["above"]):
            return False
        if "below" in vuln and v >= Version(vuln["below"]):
            return False
        if "atOrBelow" in vuln and v > Version(vuln["atOrBelow"]):
            return False
    except InvalidVersion:
        return False
    return True


def _check_vulns(display_name: str, version: str, lib_entry: dict) -> list[dict]:
    """Match detected version against retire.js vulnerability entries."""
    findings: list[dict] = []
    for vuln in lib_entry.get("vulnerabilities", []):
        if not _ver_satisfies(version, vuln):
            continue
        ids      = vuln.get("identifiers", {})
        cves     = ids.get("CVE", [])
        severity = vuln.get("severity", "medium").lower()
        severity = severity if severity in ("low", "medium", "high", "critical") else "medium"
        summary  = ids.get("summary", "") or (", ".join(cves) if cves else "Vulnerable version")
        findings.append({
            "library":          display_name,
            "detected_version": version,
            "cve":              cves[0] if cves else summary[:60],
            "cve_ids":          cves,
            "summary":          summary,
            "severity":         severity,
            "fixed_versions":   [vuln["below"]] if "below" in vuln else [],
            "references":       vuln.get("info", []),
        })
    return findings


# ── URL / HTML extraction helpers ──────────────────────────────────────────────

def _script_urls(html: str, base_url: str) -> list[str]:
    return [
        urljoin(base_url, m.group(1))
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    ]


def _link_urls(html: str, base_url: str) -> list[str]:
    return [
        urljoin(base_url, m.group(1))
        for m in re.finditer(
            r'<link[^>]+href=["\']([^"\']+\.(?:js|css)(?:[?#][^"\']*)?)["\']',
            html, re.IGNORECASE,
        )
    ]


_VERSION_RE = r"([0-9][^\s\"']*[0-9]|[0-9])"   # retire.js §§version§§ replacement


def _apply_extractors(text: str, patterns: list[str]) -> str | None:
    """Try each regex (substituting retire.js §§version§§ placeholder); return first capture."""
    for pat in patterns:
        try:
            actual = pat.replace("§§version§§", _VERSION_RE)
            m = re.search(actual, text)
            if m and m.lastindex and m.lastindex >= 1:
                v = m.group(1).strip()
                if v:
                    return v
        except re.error:
            continue
    return None


def _apply_filecontentreplace(text: str, patterns: list[str]) -> str | None:
    """
    Apply retire.js filecontentreplace patterns.

    Format: "/PATTERN/$n/" — match PATTERN, return capture group $n as the version.
    Used for minified code where the version is not in group 1 (e.g. jQuery in
    ASP.NET bundles: var a=...document,b="1.12.4",...;c.fn=c.prototype={jquery:b)
    """
    for raw in patterns:
        # Strip surrounding slashes: /PATTERN/$n/ → PATTERN/$n
        inner = raw.strip("/")
        if "/" not in inner:
            continue
        sep   = inner.rindex("/")
        pattern_str = inner[:sep]
        replacement = inner[sep + 1:]      # e.g. "$2"
        gm = re.match(r'\$(\d+)', replacement)
        if not gm:
            continue
        group_n = int(gm.group(1))
        try:
            actual = pattern_str.replace("§§version§§", _VERSION_RE)
            m = re.search(actual, text)
            if m and m.lastindex and m.lastindex >= group_n:
                v = m.group(group_n).strip()
                if v:
                    return v
        except re.error:
            continue
    return None


# ── Framework / bundler heuristics ────────────────────────────────────────────
# For modern SPAs and server-rendered frameworks that don't expose a CDN URL
# with a version number, we flag the framework as detected (version=None).

_BUNDLER_URL_RULES: list[tuple[str, list[str]]] = [
    ("Next.js",     [r"/_next/static/"]),
    ("Nuxt.js",     [r"/_nuxt/"]),
    ("Gatsby",      [r"/gatsby-", r"framework-[a-f0-9]+\.js"]),
    ("Angular",     [r"/@angular/", r"/main\.[a-f0-9]{8,}\.js"]),
    ("Svelte",      [r"/svelte/", r"svelte-[a-f0-9]"]),
    ("Remix",       [r"/__remix", r"/build/root-"]),
    ("ASP.NET MVC", [r"/bundles/\w", r"WebResource\.axd", r"ScriptResource\.axd"]),
]

_BUNDLER_HTML_RULES: list[tuple[str, list[str]]] = [
    ("React",       [r'data-reactroot', r'id=["\']root["\']']),
    ("Angular",     [r'<app-root', r'ng-version=["\']']),
    ("Vue.js",      [r'__vue_app__', r'data-v-app']),
    ("Next.js",     [r'__NEXT_DATA__', r'/_next/static/']),
    ("Nuxt.js",     [r'__NUXT_DATA__', r'__NUXT__']),
    ("Gatsby",      [r'window\.__GATSBY', r'gatsby-focus-wrapper']),
    ("Svelte",      [r'__svelte', r'data-svelte-h']),
    ("Remix",       [r'window\.__remixContext']),
    ("WordPress",   [r'wp-content', r'wp-includes']),
    ("Drupal",      [r'Drupal\.settings', r'/sites/default/files']),
    ("ASP.NET",     [r'__VIEWSTATE', r'__doPostBack', r'MicrosoftAjax']),
]


def _detect_bundler_hints(html: str, all_urls: list[str]) -> dict[str, dict]:
    hints: dict[str, dict] = {}

    for name, patterns in _BUNDLER_URL_RULES:
        if name not in hints:
            for url in all_urls:
                if any(re.search(p, url, re.IGNORECASE) for p in patterns):
                    hints[name] = {"name": name, "version": None}
                    break

    for name, patterns in _BUNDLER_HTML_RULES:
        if name not in hints:
            if any(re.search(p, html, re.IGNORECASE) for p in patterns):
                hints[name] = {"name": name, "version": None}

    # <meta name="generator"> — WordPress / Drupal / Joomla with version
    mg = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'
        r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
        html, re.IGNORECASE,
    )
    if mg:
        gen = (mg.group(1) or mg.group(2) or "").strip()
        for cms in ("WordPress", "Drupal", "Joomla"):
            m = re.match(rf'{cms}[!]?\s+([\d.]+)', gen, re.IGNORECASE)
            if m:
                hints[cms] = {"name": cms, "version": m.group(1)}

    return hints


# ── Risk helpers ───────────────────────────────────────────────────────────────
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: _RISK_ORDER.get(r, 0))


# ── Main async logic ───────────────────────────────────────────────────────────

async def _run_async(domain: str) -> dict[str, Any]:
    ssl_ctx = _permissive_ssl_ctx()
    _www    = f"www.{domain}" if not domain.startswith("www.") else domain

    def _make_client(verify_arg):
        return make_async_client(
            timeout=TIMEOUT,
            verify=verify_arg,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
        )

    async def _connect() -> tuple[httpx.Response | None, str | None]:
        for verify_arg, url in [
            (ssl_ctx, f"https://{domain}"),
            (ssl_ctx, f"https://{_www}"),
            (False,   f"http://{domain}"),
            (False,   f"http://{_www}"),
        ]:
            try:
                async with _make_client(verify_arg) as c:
                    r = await afetch(url, client=c)
                    if r.status_code < 500:
                        return r, str(r.url)
            except Exception:
                continue
        return None, None

    # Fetch homepage and retire.js DB in parallel
    (resp, base_url), db = await asyncio.gather(_connect(), _fetch_retirejs_db())

    if resp is None:
        return {
            "status": "error", "error": "Could not connect",
            "detected": [], "detected_count": 0,
            "vulnerabilities": [], "cve_count": 0,
            "critical_count": 0, "high_count": 0,
            "risk": "low", "findings": [],
        }

    html        = resp.text
    script_urls = _script_urls(html, base_url)
    all_urls    = script_urls + _link_urls(html, base_url)

    # ── Phase 1: URL-based extraction ─────────────────────────────────────────
    detected: dict[str, dict] = {}   # lib_id → {name, version}

    for lib_id, lib_entry in db.items():
        exts     = lib_entry.get("extractors", {})
        uri_pats = exts.get("uri", []) + exts.get("filename", [])
        if not uri_pats:
            continue
        for url in all_urls:
            parsed   = urlparse(url)
            url_text = parsed.path + ("?" + parsed.query if parsed.query else "")
            v = _apply_extractors(url_text, uri_pats)
            if v:
                detected[lib_id] = {"name": lib_id, "version": v}
                break

    # ── Phase 2: Content-based extraction ─────────────────────────────────────
    unresolved = {
        lib_id: lib_entry
        for lib_id, lib_entry in db.items()
        if lib_id not in detected
        and (
            lib_entry.get("extractors", {}).get("filecontent")
            or lib_entry.get("extractors", {}).get("filecontentreplace")
        )
    }

    if unresolved and script_urls:
        sem = asyncio.Semaphore(CONCURRENCY)

        async def fetch_banner(url: str) -> tuple[str, str]:
            async with sem:
                for verify_arg in (ssl_ctx, False):
                    try:
                        async with _make_client(verify_arg) as c:
                            r = await afetch(url, client=c, headers={"Range": f"bytes=0-{BANNER_SIZE - 1}"},
                                             max_bytes=BANNER_SIZE)
                            return url, r.text[:BANNER_SIZE]
                    except Exception:
                        continue
                return url, ""

        # Prioritise bundle URLs — they contain concatenated libs
        bundles = [u for u in script_urls if re.search(r'/bundle[s]?[/?]', u, re.I)]
        others  = [u for u in script_urls if u not in bundles]
        ordered = bundles + others

        contents = await asyncio.gather(*[fetch_banner(u) for u in ordered[:30]])

        for _url, content in contents:
            if not unresolved:
                break          # all libs found, no need to scan more files
            if not content:
                continue       # this fetch failed, try next script
            for lib_id in list(unresolved.keys()):
                exts = unresolved[lib_id].get("extractors", {})
                pats = exts.get("filecontent", [])
                v = _apply_extractors(content, pats)
                if v is None:
                    # Try filecontentreplace (regex substitution patterns)
                    v = _apply_filecontentreplace(content, exts.get("filecontentreplace", []))
                if v:
                    detected[lib_id] = {"name": lib_id, "version": v}
                    del unresolved[lib_id]

    # ── Phase 3: Bundler / framework heuristics ────────────────────────────────
    for name, info in _detect_bundler_hints(html, all_urls).items():
        if name not in detected:
            detected[name] = info

    # ── Phase 4: Vulnerability matching ───────────────────────────────────────
    all_vulns: list[dict] = []
    for lib_id, info in detected.items():
        version = info.get("version")
        if not version:
            continue
        lib_entry = db.get(lib_id, {})
        all_vulns.extend(_check_vulns(info["name"], version, lib_entry))

    # ── Build response ─────────────────────────────────────────────────────────
    detected_list = [
        {
            "name":       info["name"],
            "npm":        lib_id,
            "version":    info.get("version") or "unknown",
            "vuln_count": sum(1 for v in all_vulns if v["library"] == info["name"]),
        }
        for lib_id, info in detected.items()
    ]

    cve_count      = len(all_vulns)
    critical_count = sum(1 for v in all_vulns if v["severity"] == "critical")
    high_count     = sum(1 for v in all_vulns if v["severity"] == "high")

    risk = "low"
    if critical_count:
        risk = "critical"
    elif high_count:
        risk = "high"
    elif cve_count:
        risk = "medium"

    findings = [
        (
            f"[{v['severity'].upper()}] {v['library']} {v['detected_version']}: "
            f"{v['cve']} — {v['summary']}"
            + (f" (fix: {v['fixed_versions'][0]})" if v['fixed_versions'] else "")
        )
        for v in all_vulns
    ]

    return {
        "status":          "ok",
        "detected":        detected_list,
        "detected_count":  len(detected_list),
        "vulnerabilities": all_vulns,
        "cve_count":       cve_count,
        "critical_count":  critical_count,
        "high_count":      high_count,
        "risk":            risk,
        "findings":        findings,
    }


def run(domain: str) -> dict[str, Any]:
    """Synchronous entry point called from main.py pipeline."""
    try:
        return asyncio.run(_run_async(domain))
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error", "error": str(exc),
            "detected": [], "detected_count": 0,
            "vulnerabilities": [], "cve_count": 0,
            "critical_count": 0, "high_count": 0,
            "risk": "low", "findings": [],
        }

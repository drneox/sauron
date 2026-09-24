"""
Smart Fuzz — unified, calibrated path-discovery engine.

Replaces ad-hoc wordlist probing with a single engine that:
  1. Loads curated wordlists from backend/data/wordlists/ (common + per-stack
     + industry). wordlist="auto" picks common.txt plus the stack list(s)
     matching `tech_hints` (technology names from tech_fingerprint) and
     seguros.txt when the brand looks like a LATAM insurer.
  2. Optionally asks the LLM for directed paths (`_llm_directed_paths`):
     prefixes derived from JS-mined endpoints, per-stack checks, per-sector
     guesses. Directed paths are probed FIRST, flagged "directed": true and
     bumped one severity notch on match.
  3. Applies the same anti-false-positive calibration as exposed_files by
     IMPORTING its helpers (baseline with random-404 hashes, homepage
     catch-all ±5%, median-200, magic bytes, content signatures, WAF block
     page detection). Nothing is duplicated here on purpose.

Anti-WAF politeness: if the baseline sees a WAF block page, or a wall of
identical 403s suppresses nearly every probe, the run cuts early and reports
waf_blocked=True instead of hammering the target.

Contract: run(domain, ...) -> dict with keys
  status, wordlist_used, requests_made, paths_found, waf_blocked, risk, findings.
"""
import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any

import httpx

from modules.common import afetch, is_same_path_redirect, make_async_client
from modules.exposed_files import (
    SEVERITY_ORDER,
    _body_hash,
    _body_hash_full,
    _check_magic,
    _content_validates,
    _get_baseline,
    _has_waf_header,
    _is_html_response,
    _is_waf_block_page,
    _should_reject_html,
    _similar_size,
)

logger = logging.getLogger(__name__)

_WORDLIST_DIR = Path(__file__).resolve().parent.parent / "data" / "wordlists"

MAX_REQUESTS_CAP = 10_000
DEFAULT_MAX_REQUESTS = 2_000
AGENT_MAX_REQUESTS = 500          # cap when the LLM agent calls the tool
LLM_DIRECTED_LIMIT = 40
_CONCURRENCY = 12
_PROBE_TIMEOUT = 8.0
# After this many probes, if virtually every response is a suppressed 403 wall
# we stop early: the WAF is answering everything and results would be garbage.
_WALL_CHECK_MIN_PROBES = 40
_WALL_SUPPRESS_RATIO = 0.9

# ── Wordlist selection ────────────────────────────────────────────────────────

# tech_hints substring (lowercase) -> wordlist file
_STACK_HINTS = {
    "laravel": "laravel.txt",
    "wordpress": "wordpress.txt",
    "spring": "spring.txt",
    "php": "php.txt",
    "react": "spa.txt",
    "vue": "spa.txt",
    "angular": "spa.txt",
    "next.js": "spa.txt",
    "nuxt": "spa.txt",
    "svelte": "spa.txt",
}

# Insurance-brand heuristic: seguros.txt is included when the domain is a
# Peruvian TLD (.pe) or the brand label contains a well-known insurer marker.
# Deliberately simple and documented — refine when company context lands.
_INSURANCE_MARKERS = (
    "seguro", "pacifico", "prima", "rimac", "mapfre", "positiva",
    "interseguro", "avla", "chubb", "aseguradora",
)


def _load_wordlist(name: str) -> list[str]:
    path = _WORDLIST_DIR / name
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.warning(f"[smart_fuzz] cannot read wordlist {name}: {e}")
        return []
    out = []
    for line in lines:
        entry = line.strip()
        if entry and not entry.startswith("#"):
            out.append(entry)
    return out


def _normalize_entry(entry: str) -> str | None:
    """Force a clean absolute path; reject junk (schemes, hosts, traversal)."""
    entry = entry.strip()
    if not entry or "://" in entry or entry.startswith("?") or ".." in entry:
        return None
    if not entry.startswith("/"):
        entry = "/" + entry
    if len(entry) > 200:
        return None
    return entry


def _looks_like_insurer(domain: str) -> bool:
    d = domain.lower()
    if d.endswith(".pe") or ".pe" in d.split(":")[0]:
        return True
    brand = d.split(".")[0].split(":")[0]
    return any(m in brand for m in _INSURANCE_MARKERS)


def _select_wordlists(
    domain: str,
    wordlist: str,
    tech_hints: list[str] | None,
    known_endpoints: list[str] | None,
) -> tuple[list[str], list[str]]:
    """Return (ordered paths, wordlist names used)."""
    if wordlist != "auto":
        paths = _load_wordlist(wordlist if wordlist.endswith(".txt") else wordlist + ".txt")
        return paths, [wordlist]

    names: list[str] = []
    hints = [str(h).lower() for h in (tech_hints or [])]
    seen_files: set[str] = set()
    for hint in hints:
        for needle, fname in _STACK_HINTS.items():
            if needle in hint and fname not in seen_files:
                seen_files.add(fname)
                names.append(fname)
    # JS-mined endpoints imply an API exists — always worth the API wordlist.
    if known_endpoints and "api.txt" not in seen_files:
        names.append("api.txt")
    if _looks_like_insurer(domain) and "seguros.txt" not in seen_files:
        names.append("seguros.txt")
    # common.txt goes last: stack/industry lists are higher-signal per request.
    names.append("common.txt")

    paths: list[str] = []
    for fname in names:
        paths.extend(_load_wordlist(fname))
    return paths, names


# ── Severity heuristics ───────────────────────────────────────────────────────

_SEVERITY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.env($|\.)|/\.git/|/\.svn/|/\.hg/|heapdump|/actuator/env|"
                r"\.sql$|\.sqlite3?$|dump|backup\.(zip|tar|gz|7z|sql)|"
                r"wp-config|database\.yml|\.pem$|\.key$|id_rsa|terraform\.tfstate", re.I), "critical"),
    (re.compile(r"/telescope|/horizon|/_debugbar|/_ignition|/actuator/|/jolokia|"
                r"phpinfo|/elmah|/trace\.axd|/h2-console|/server-status|/server-info|"
                r"laravel\.log|error\.log|debug\.log|access\.log|/\.DS_Store|"
                r"composer\.(json|lock)|/vendor/|/console($|/)", re.I), "high"),
    (re.compile(r"/admin($|/)|/swagger|/openapi|/api-docs|/graphql|/graphiql|"
                r"/metrics$|/prometheus|/config|/debug($|/)|/api/v\d|"
                r"manifest\.json|asset-manifest|/wp-json|/xmlrpc\.php|"
                r"/actuator($|/)", re.I), "medium"),
]


def _base_severity(path: str) -> str:
    for pattern, sev in _SEVERITY_RULES:
        if pattern.search(path):
            return sev
    return "low"


def _bump(severity: str) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    idx = order.index(severity) if severity in order else 1
    return order[min(len(order) - 1, idx + 1)]


# ── LLM-directed paths ────────────────────────────────────────────────────────

_LLM_SYSTEM = (
    "You are an offensive-security web fuzzing planner. Given a target domain, its "
    "detected technologies, endpoints already mined from its JavaScript, and brand/sector "
    "context, propose up to 40 URL paths worth probing on that host (admin panels, config "
    "files, debug endpoints, API siblings of the known endpoints, sector-specific portals). "
    "Rules: paths must start with '/', never include scheme/host/query, never use '..', "
    "reuse prefixes seen in the known endpoints (e.g. /api/v1/cotizar -> /api/v1/users), "
    "include stack-specific checks for the detected technologies. "
    'Respond ONLY with a JSON object {"paths": ["..."]}.'
)


def _llm_directed_paths(
    domain: str,
    tech_findings: list[str] | None,
    endpoints_conocidos: list[str] | None,
    company_context: str | None = None,
) -> list[str]:
    """One LLM call proposing directed paths. [] silently when no key / on error."""
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        return []
    from modules.ai_summary import _chat_request, _endpoint_and_headers  # noqa: F401 — reuse, don't duplicate

    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")

    user = {
        "domain": domain,
        "technologies": (tech_findings or [])[:30],
        "known_endpoints": (endpoints_conocidos or [])[:50],
        "company_context": (company_context or "")[:300],
    }
    try:
        import json as _json
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": _LLM_SYSTEM},
                {"role": "user", "content": _json.dumps(user, ensure_ascii=False)},
            ],
            "temperature": 0.3,
            "response_format": {"type": "json_object"},
        }
        with httpx.Client(timeout=45) as client:
            data = _chat_request(client, base_url, api_key, payload)
        content = data["choices"][0]["message"]["content"]
        parsed = _json.loads(content)
        raw = parsed.get("paths") or []
    except Exception as e:
        logger.warning(f"[smart_fuzz] LLM-directed paths failed: {e}")
        return []

    out: list[str] = []
    for p in raw:
        if not isinstance(p, str):
            continue
        norm = _normalize_entry(p)
        if norm and norm not in out:
            out.append(norm)
        if len(out) >= LLM_DIRECTED_LIMIT:
            break
    return out


# ── Probe engine ──────────────────────────────────────────────────────────────

async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    severity: str,
    directed: bool,
    semaphore: asyncio.Semaphore,
    baseline: dict,
    min_delay: float,
    stats: dict,
) -> dict | None:
    async with semaphore:
        if min_delay > 0:
            await asyncio.sleep(min_delay)
        url = base_url.rstrip("/") + path
        try:
            resp = await afetch(url, client=client, allow_redirects=False)
        except Exception as e:
            stats["errors"] += 1
            logger.debug(f"[smart_fuzz] {url}: {e}")
            return None
        stats["requests"] += 1

        code = resp.status_code
        body = resp.content
        body_size = len(body)
        content_type = resp.headers.get("content-type", "")

        # ── 200 / 206: run the exposed_files calibration chain ────────────
        if code in (200, 206):
            if _is_waf_block_page(body):
                stats["waf_pages"] += 1
                return None
            body_hash = _body_hash(body)
            if body_hash in baseline["hashes_200"]:
                return None
            full_hash = _body_hash_full(body)
            if full_hash in baseline["full_hashes_200"]:
                return None
            if baseline["homepage_full_hash"] and full_hash == baseline["homepage_full_hash"]:
                return None
            if baseline["homepage_size"] and _similar_size(body_size, baseline["homepage_size"]):
                return None
            if baseline["returns_200"] and baseline["median_200"] and _similar_size(body_size, baseline["median_200"]):
                return None
            if body_size < 20:
                return None
            body_text = body.decode("utf-8", errors="replace")
            if body_size < 4000:
                lower = body_text.lower()
                if any(kw in lower for kw in [
                    "404", "not found", "page not found", "no encontrado",
                    "doesn't exist", "does not exist", "no existe", "error 404",
                    "could not be found", "nothing here", "no page",
                ]):
                    return None
            if not _check_magic(path, body):
                return None
            if _should_reject_html(path) and _is_html_response(content_type):
                return None
            if not _content_validates(path, body_text):
                return None
            evidence = body_text[:150].replace("\n", " ").strip()
            return _make_hit(path, url, code, body_size, severity, directed, evidence)

        # ── Redirects: record as informational (target may sit behind login) ──
        if code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            norm_location = location.rstrip("/")
            # Catch-all redirects to the homepage are noise, not a hit.
            if norm_location in ("", "/", base_url.rstrip("/")):
                return None
            # Canonical-host / http->https / trailing-slash redirect to the very
            # same path: the site's default behavior, not evidence of this path.
            if is_same_path_redirect(url, location):
                stats["wall_redirect"] += 1
                return None
            # Redirect wall: random non-existent paths in the baseline bounced
            # to this same target (e.g. every unauthenticated path -> /login).
            # A probe landing on the same target proves nothing about that
            # specific path existing — it's the site's default behavior.
            if baseline.get("redirect_wall_target") and norm_location == baseline["redirect_wall_target"]:
                stats["wall_redirect"] += 1
                return None
            if _base_severity(path) in ("critical", "high", "medium"):
                return _make_hit(path, url, code, body_size, "low", directed,
                                 f"redirect -> {location[:120]}")
            return None

        # ── 401 / 403: exists but protected — only meaningful if the server
        #    does NOT answer random garbage with the same code (baseline) ────
        if code in (401, 403):
            if _is_waf_block_page(body):
                stats["waf_pages"] += 1
                return None
            if baseline["returns_403"]:
                stats["wall_403"] += 1
                return None
            body_hash = _body_hash(body)
            if body_hash in baseline["hashes_403"]:
                stats["wall_403"] += 1
                return None
            if baseline["wall_size"] is not None and body_size == baseline["wall_size"]:
                stats["wall_403"] += 1
                return None
            if baseline["waf_on_baseline"] and _has_waf_header(resp.headers):
                stats["wall_403"] += 1
                return None
            sev = _base_severity(path)
            if sev in ("critical", "high", "medium"):
                note = "auth required" if code == 401 else "access forbidden — likely exists"
                # Access is denied: nothing is exposed, so this stays inventory
                # ("low"), never a finding. _hash is internal, stripped in
                # _run_async after the same-run wall check.
                hit = _make_hit(path, url, code, body_size, "low", directed, f"HTTP {code} ({note})")
                hit["_hash"] = body_hash
                return hit
            return None

        return None


def _make_hit(path, url, status, size, severity, directed, evidence) -> dict:
    # Redirects and 401/403 stay "low" even when LLM-directed: a bump would surface
    # them as MEDIUM findings although nothing proves the path is exposed.
    if directed and status not in (301, 302, 303, 307, 308, 401, 403):
        severity = _bump(severity)
    return {
        "path": path,
        "url": url,
        "status": status,
        "size": size,
        "severity": severity,
        "evidence": evidence or None,
        "directed": directed,
    }


async def _run_async(
    domain: str,
    probes: list[tuple[str, bool]],   # (path, directed) already deduped, ordered
    max_requests: int,
    min_delay: float,
    wordlist_names: list[str],
) -> dict[str, Any]:
    base_url = f"https://{domain}"
    limits = httpx.Limits(max_connections=25, max_keepalive_connections=10)
    stats = {"requests": 0, "errors": 0, "waf_pages": 0, "wall_403": 0, "wall_redirect": 0}
    async with make_async_client(
        timeout=httpx.Timeout(_PROBE_TIMEOUT),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
        limits=limits,
    ) as client:
        try:
            r = await afetch(base_url, client=client)
            if r.status_code >= 500:
                raise ValueError("server error")
        except Exception:
            base_url = f"http://{domain}"

        baseline = await _get_baseline(client, base_url)
        logger.debug(
            f"[smart_fuzz] baseline: 403_random={baseline['returns_403']} "
            f"200_random={baseline['returns_200']} waf={baseline['waf_on_baseline']} "
            f"waf_blocked={baseline['waf_blocked']}"
        )

        waf_blocked = bool(baseline["waf_blocked"])
        found: list[dict] = []
        if waf_blocked:
            logger.info(f"[smart_fuzz] {domain}: WAF block page on baseline — cutting early")
        else:
            semaphore = asyncio.Semaphore(_CONCURRENCY)
            done = 0
            for chunk_start in range(0, len(probes), _CONCURRENCY * 4):
                if stats["requests"] >= max_requests:
                    break
                chunk = probes[chunk_start: chunk_start + _CONCURRENCY * 4]
                results = await asyncio.gather(*[
                    _probe_path(client, base_url, p, _base_severity(p), d,
                                semaphore, baseline, min_delay, stats)
                    for p, d in chunk
                ])
                found.extend(r for r in results if r is not None)
                done += len(chunk)
                # 403-wall early cut: nearly everything suppressed by the wall
                if done >= _WALL_CHECK_MIN_PROBES and stats["wall_403"] / done >= _WALL_SUPPRESS_RATIO:
                    waf_blocked = True
                    logger.info(
                        f"[smart_fuzz] {domain}: 403 wall after {done} probes — cutting early"
                    )
                    break
                # Redirect-wall early cut: everything unauthenticated bounces to
                # the same target (e.g. a global login gate) — no point burning
                # the rest of the budget on probes that can never resolve.
                if done >= _WALL_CHECK_MIN_PROBES and stats["wall_redirect"] / done >= _WALL_SUPPRESS_RATIO:
                    waf_blocked = True
                    logger.info(
                        f"[smart_fuzz] {domain}: redirect wall after {done} probes — cutting early"
                    )
                    break

    # Same-run wall check: several sensitive-looking paths answering 401/403 with a
    # byte-identical body is a WAF/catch-all blocking by pattern (the random-path
    # baseline can't see it — it never probes sensitive-looking names).
    hash_counts: dict[str, int] = {}
    for f in found:
        if f.get("_hash"):
            hash_counts[f["_hash"]] = hash_counts.get(f["_hash"], 0) + 1
    wall_hashes = {h for h, c in hash_counts.items() if c >= 3}
    suppressed_count = sum(1 for f in found if f.get("_hash") in wall_hashes)
    if suppressed_count:
        logger.info(f"[smart_fuzz] {domain}: suppressing {suppressed_count} 401/403 hit(s) sharing an identical body")
        found = [f for f in found if f.get("_hash") not in wall_hashes]
    for f in found:
        f.pop("_hash", None)

    _conf_directed = {True: 0, False: 1}
    found.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), _conf_directed[x["directed"]]))

    risk = "low"
    for f in found:
        if SEVERITY_ORDER.get(f["severity"], 0) > SEVERITY_ORDER.get(risk, 0):
            risk = f["severity"]

    findings = []
    if waf_blocked:
        findings.append(
            "[INFO] WAF blocking fuzzing (block page or uniform 403 wall) — "
            "path discovery cut short; results are a lower bound"
        )
    if suppressed_count:
        findings.append(
            f"[INFO] Suppressed {suppressed_count} sensitive-path 401/403 hit(s) sharing an "
            "identical response body — WAF/catch-all wall, not confirmed paths"
        )
    for f in found:
        if f["severity"] in ("critical", "high", "medium"):
            tag = " [LLM-directed]" if f["directed"] else ""
            findings.append(
                f"[{f['severity'].upper()}] Path discovered{tag}: {f['path']} "
                f"(HTTP {f['status']}, {f['size']} bytes)"
            )

    return {
        "status": "ok",
        "wordlist_used": wordlist_names,
        "requests_made": stats["requests"],
        "paths_found": found,
        "waf_blocked": waf_blocked,
        "risk": risk,
        "findings": findings,
    }


# ── Entry point ───────────────────────────────────────────────────────────────

def run(
    domain: str,
    wordlist: str = "auto",
    max_requests: int = DEFAULT_MAX_REQUESTS,
    llm_paths: list[str] | None = None,
    tech_hints: list[str] | None = None,
    known_endpoints: list[str] | None = None,
    company_context: str | None = None,
    min_delay: float = 0.0,
    enable_llm: bool = True,
) -> dict[str, Any]:
    """Probe `domain` for hidden paths.

    wordlist: "auto" (stack/sector-aware selection) or a wordlist name.
    llm_paths: explicit directed paths; when None and enable_llm, they are
      requested from the LLM using tech_hints + known_endpoints.
    max_requests: probe budget (hard cap MAX_REQUESTS_CAP); baseline excluded.
    min_delay: seconds between requests per worker (politeness, default 0).
    """
    import warnings
    warnings.filterwarnings("ignore")

    try:
        max_requests = max(1, min(int(max_requests or DEFAULT_MAX_REQUESTS), MAX_REQUESTS_CAP))
    except (TypeError, ValueError):
        max_requests = DEFAULT_MAX_REQUESTS

    if llm_paths is None and enable_llm:
        llm_paths = _llm_directed_paths(domain, tech_hints, known_endpoints, company_context)
    llm_paths = llm_paths or []

    wl_paths, wl_names = _select_wordlists(domain, wordlist, tech_hints, known_endpoints)

    # Directed paths first, then the wordlists; dedupe preserving priority.
    probes: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for p in llm_paths:
        norm = _normalize_entry(p)
        if norm and norm not in seen:
            seen.add(norm)
            probes.append((norm, True))
    for p in wl_paths:
        norm = _normalize_entry(p)
        if norm and norm not in seen:
            seen.add(norm)
            probes.append((norm, False))
    probes = probes[:max_requests]

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            _run_async(domain, probes, max_requests, max(0.0, float(min_delay)), wl_names)
        )
        loop.close()
        result["directed_count"] = sum(1 for p, d in probes if d)
        return result
    except Exception as e:
        logger.error(f"[smart_fuzz] {domain}: {e}")
        return {
            "status": "error", "error": str(e),
            "wordlist_used": wl_names, "requests_made": 0,
            "paths_found": [], "waf_blocked": False,
            "risk": "low", "findings": [],
        }

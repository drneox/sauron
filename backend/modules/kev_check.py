"""
kev_check.py — known-exploited vulnerabilities in the detected technologies.

CISA's KEV catalog lists CVEs that are being exploited in the wild right now,
which makes it a far better signal than "a CVE exists for this product". KEV
says which product, but not which versions, so every candidate CVE is checked
against NVD's affected-version ranges before anything is reported:

  detected tech + version ──► KEV entries for that product ──► NVD ranges ──► finding
                                                                (version inside?)

Rules that keep it honest:
  - no version detected  → nothing is reported (listed as "unverifiable")
  - NVD has no ranges for the CVE / NVD unreachable → nothing is reported
    (listed as "unverified"); never a finding on a guess
  - the version comes from headers/HTML, so a vendor backport can hide a fix:
    the finding says "verify", and nuclei confirms when a template exists

Network use: one KEV download per 24 h, one NVD lookup per candidate CVE per
30 days (both cached in memory and in modules/data/). NVD allows 5 requests
per 30 s without a key, 50 with NVD_API_KEY.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from modules import tech_fingerprint

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEV_TTL = 86_400            # 24 h
NVD_TTL = 30 * 86_400       # affected ranges rarely change
NVD_EMPTY_TTL = 86_400      # NVD sometimes lacks configurations for fresh CVEs: retry daily
RUN_BUDGET = 100            # seconds of NVD lookups per run
MAX_CANDIDATES_PER_TECH = 25

_DATA_DIR = Path(__file__).parent / "data"
_KEV_CACHE_PATH = _DATA_DIR / "kev_cache.json"
_NVD_CACHE_PATH = _DATA_DIR / "nvd_cache.json"

# detected technology → (KEV vendorProject regex, KEV product regex, NVD CPE product names)
CORE_PRODUCTS: dict[str, tuple[str, str, set[str]]] = {
    "Apache": (r"^apache$", r"^http server$", {"httpserver"}),
    "Tomcat": (r"^apache$", r"^tomcat$", {"tomcat"}),
    "PHP": (r"^php( group)?$", r"^php$", {"php"}),
    "WordPress": (r"^wordpress$", r"^core$", {"wordpress"}),
    "Drupal": (r"^drupal$", r"core", {"drupal"}),
    "Joomla": (r"^joomla!?$", r"^joomla!?$", {"joomla"}),
    "IIS": (r"^microsoft$", r"internet information services", {"internetinformationservices"}),
    "Magento": (r"^adobe$", r"magento", {"magento", "commerce"}),
    "Laravel": (r"^laravel$", r"laravel framework", {"laravel"}),
    "Nginx": (r"^(f5|nginx)$", r"nginx", {"nginx"}),
    "phpMyAdmin": (r"^phpmyadmin$", r"phpmyadmin", {"phpmyadmin"}),
}

_PLUGIN_RE = re.compile(r"^(?P<slug>[\w\-]+) \(WP (?P<kind>plugin|theme)\)$")
_SLUG_NOISE = {"wp", "wordpress", "plugin", "theme", "for", "the", "by"}

_lock = threading.Lock()          # guards the in-memory caches and disk writes
_nvd_gate = threading.Lock()      # serializes NVD requests (rate limit)
_last_nvd_call = 0.0
_kev_mem: tuple[float, list[dict]] | None = None
_nvd_mem: dict[str, dict] | None = None


# ── pure helpers (unit-tested) ───────────────────────────────────────────────

def _norm(text: str) -> str:
    """Lowercase alphanumerics only: "wp-file-manager" == "WP_File_Manager"."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def parse_version(raw: str | None) -> Version | None:
    """Leading numeric version of a detected string ("7.4.3-1ubuntu2" → 7.4.3)."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", raw or "")
    if not m:
        return None
    try:
        return Version(m.group(1))
    except InvalidVersion:
        return None


def _slug_words(slug: str) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9]+", slug.lower()) if w and w not in _SLUG_NOISE]


def plugin_matches_product(slug: str, kev_product: str) -> bool:
    """A WordPress plugin slug against a KEV product name: every meaningful slug
    word must appear in the product ("wp-file-manager" ↔ "File Manager Plugin")."""
    words = _slug_words(slug)
    product = (kev_product or "").lower()
    if not words or not re.search(r"plugin|theme", product):
        return False
    product_words = set(re.split(r"[^a-z0-9]+", product))
    return all(w in product_words for w in words)


def kev_candidates(technology: str, catalog: list[dict]) -> tuple[list[dict], set[str]]:
    """KEV entries that could apply to `technology`, plus the NVD CPE product
    names that count as "the same product" when reading affected ranges."""
    core = CORE_PRODUCTS.get(technology)
    if core:
        vendor_re, product_re, cpe_products = core
        hits = [e for e in catalog
                if re.search(vendor_re, (e.get("vendorProject") or "").strip(), re.I)
                and re.search(product_re, (e.get("product") or "").strip(), re.I)]
        return hits[:MAX_CANDIDATES_PER_TECH], cpe_products
    m = _PLUGIN_RE.match(technology)
    if m:
        slug = m.group("slug")
        hits = [e for e in catalog
                if re.fullmatch(r"wordpress", (e.get("vendorProject") or "").strip(), re.I)
                and plugin_matches_product(slug, e.get("product") or "")]
        return hits[:MAX_CANDIDATES_PER_TECH], {_norm(slug)}
    return [], set()


def _cpe_parts(criteria: str) -> tuple[str, str]:
    """(product, version) of a cpe:2.3:<part>:<vendor>:<product>:<version>:… string."""
    parts = re.split(r"(?<!\\):", criteria)
    product = parts[4] if len(parts) > 4 else ""
    version = parts[5] if len(parts) > 5 else "*"
    return _norm(product.replace("\\", "")), version


def extract_ranges(nvd_cve: dict) -> list[dict]:
    """Vulnerable cpeMatch rows of an NVD CVE, reduced to what version checking needs."""
    out: list[dict] = []
    for conf in nvd_cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                product, version = _cpe_parts(m.get("criteria") or "")
                out.append({
                    "product": product,
                    "version": version,
                    "start_incl": m.get("versionStartIncluding"),
                    "start_excl": m.get("versionStartExcluding"),
                    "end_incl": m.get("versionEndIncluding"),
                    "end_excl": m.get("versionEndExcluding"),
                })
    return out


def version_affected(version: Version, ranges: list[dict], cpe_products: set[str]) -> str | None:
    """Human-readable affected range if `version` falls inside one of the ranges
    of a matching product, else None."""
    for r in ranges:
        product = r["product"]
        if not any(product == p or (len(p) >= 4 and p in product) for p in cpe_products):
            continue
        exact = r["version"]
        if exact not in ("*", "-", ""):
            ev = parse_version(exact)
            if ev is not None and ev == version:
                return exact
            continue
        bounds = {k: parse_version(r[k]) if r[k] else None
                  for k in ("start_incl", "start_excl", "end_incl", "end_excl")}
        if not any(r[k] for k in ("start_incl", "start_excl", "end_incl", "end_excl")):
            continue  # "every version" wildcard with no bounds carries no information
        if bounds["start_incl"] and version < bounds["start_incl"]:
            continue
        if bounds["start_excl"] and version <= bounds["start_excl"]:
            continue
        if bounds["end_incl"] and version > bounds["end_incl"]:
            continue
        if bounds["end_excl"] and version >= bounds["end_excl"]:
            continue
        return _describe_range(r)
    return None


def _describe_range(r: dict) -> str:
    lo = f">= {r['start_incl']}" if r["start_incl"] else (f"> {r['start_excl']}" if r["start_excl"] else "")
    hi = f"<= {r['end_incl']}" if r["end_incl"] else (f"< {r['end_excl']}" if r["end_excl"] else "")
    return ", ".join(x for x in (lo, hi) if x)


def build_finding(technology: str, version: str, entry: dict, affected: str) -> str:
    text = (
        f"[KEV] {technology} {version} is within the affected range ({affected}) of "
        f"{entry['cveID']} — {entry.get('vulnerabilityName') or 'known exploited vulnerability'}, "
        f"exploited in the wild (CISA KEV, added {entry.get('dateAdded')})"
    )
    if (entry.get("knownRansomwareCampaignUse") or "").lower() == "known":
        text += "; used in ransomware campaigns"
    text += ". Version comes from the response and vendors may backport fixes — verify the real build."
    return text


# ── data sources ─────────────────────────────────────────────────────────────

def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _write_json(path: Path, payload: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload))
        tmp.replace(path)
    except Exception as exc:
        logger.warning(f"[kev] could not write {path.name}: {exc}")


def _load_kev() -> list[dict] | None:
    """The KEV catalog (memory → disk → CISA); a stale copy beats no data."""
    global _kev_mem
    now = time.time()
    with _lock:
        if _kev_mem and now - _kev_mem[0] < KEV_TTL:
            return _kev_mem[1]
        disk = _read_json(_KEV_CACHE_PATH)
        if isinstance(disk, dict) and now - disk.get("fetched", 0) < KEV_TTL and disk.get("entries"):
            _kev_mem = (disk["fetched"], disk["entries"])
            return _kev_mem[1]
        try:
            resp = httpx.get(KEV_URL, timeout=30, follow_redirects=True,
                             headers={"User-Agent": "Sauron-ASM"})
            resp.raise_for_status()
            entries = resp.json().get("vulnerabilities") or []
            if not entries:
                raise ValueError("empty catalog")
            _kev_mem = (now, entries)
            _write_json(_KEV_CACHE_PATH, {"fetched": now, "entries": entries})
            return entries
        except Exception as exc:
            logger.warning(f"[kev] CISA catalog unavailable: {exc}")
            stale = (disk or {}).get("entries") if isinstance(disk, dict) else None
            if stale:
                _kev_mem = (now - KEV_TTL + 3600, stale)  # retry in an hour
                return stale
            return None


def _nvd_cache() -> dict[str, dict]:
    global _nvd_mem
    if _nvd_mem is None:
        disk = _read_json(_NVD_CACHE_PATH)
        _nvd_mem = disk if isinstance(disk, dict) else {}
    return _nvd_mem


def _cached_ranges(cve: str) -> list[dict] | None:
    with _lock:
        row = _nvd_cache().get(cve)
    if not row:
        return None
    ttl = NVD_TTL if row.get("ranges") else NVD_EMPTY_TTL
    return row["ranges"] if time.time() - row.get("fetched", 0) < ttl else None


def _nvd_ranges(cve: str, deadline: float) -> list[dict] | None:
    """Affected ranges from NVD (cached); None when unavailable or out of budget."""
    cached = _cached_ranges(cve)
    if cached is not None:
        return cached
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    spacing = 0.7 if api_key else 6.5
    global _last_nvd_call
    with _nvd_gate:
        cached = _cached_ranges(cve)  # another thread may have fetched it while we waited
        if cached is not None:
            return cached
        wait = _last_nvd_call + spacing - time.time()
        if wait > 0:
            if time.time() + wait > deadline:
                return None
            time.sleep(wait)
        if time.time() > deadline:
            return None
        headers = {"User-Agent": "Sauron-ASM"}
        if api_key:
            headers["apiKey"] = api_key
        try:
            resp = httpx.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=20)
            _last_nvd_call = time.time()
            if resp.status_code in (403, 429):
                logger.warning(f"[kev] NVD rate limited on {cve}")
                return None
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities") or []
            ranges = extract_ranges(vulns[0]["cve"]) if vulns else []
        except Exception as exc:
            _last_nvd_call = time.time()
            logger.warning(f"[kev] NVD lookup failed for {cve}: {exc}")
            return None
        with _lock:
            _nvd_cache()[cve] = {"fetched": time.time(), "ranges": ranges}
            _write_json(_NVD_CACHE_PATH, _nvd_cache())
        return ranges


# ── module entry point ───────────────────────────────────────────────────────

def _empty(status: str = "ok", **extra: Any) -> dict[str, Any]:
    return {"status": status, "matches": [], "unverifiable": [], "unverified": [],
            "checked": [], "risk": "low", "findings": [], **extra}


def run(domain: str) -> dict[str, Any]:
    try:
        tech = tech_fingerprint.run(domain)
    except Exception as exc:
        return _empty("error", error=str(exc))
    if tech.get("status") != "ok":
        return _empty("skipped", reason="technology detection failed")
    technologies = tech.get("technologies") or []
    versions = tech.get("versions") or {}

    catalog = _load_kev()
    if catalog is None:
        return _empty("skipped", reason="CISA KEV catalog unavailable")

    result = _empty()
    deadline = time.time() + RUN_BUDGET
    seen: set[tuple[str, str]] = set()
    for technology in technologies:
        candidates, cpe_products = kev_candidates(technology, catalog)
        if not candidates:
            continue
        raw_version = versions.get(technology)
        version = parse_version(raw_version)
        result["checked"].append({"technology": technology, "version": raw_version,
                                  "candidates": len(candidates)})
        if version is None:
            result["unverifiable"].append({
                "technology": technology, "candidates": len(candidates),
                "reason": "version not exposed",
            })
            continue
        for entry in candidates:
            cve = entry["cveID"]
            ranges = _nvd_ranges(cve, deadline)
            if not ranges:
                result["unverified"].append(cve)
                continue
            affected = version_affected(version, ranges, cpe_products)
            if affected and (technology, cve) not in seen:
                seen.add((technology, cve))
                result["matches"].append({
                    "cve": cve, "technology": technology, "version": raw_version,
                    "name": entry.get("vulnerabilityName"), "affected_range": affected,
                    "date_added": entry.get("dateAdded"), "due_date": entry.get("dueDate"),
                    "ransomware": (entry.get("knownRansomwareCampaignUse") or "").lower() == "known",
                    "required_action": entry.get("requiredAction"),
                })
                result["findings"].append(build_finding(technology, raw_version, entry, affected))

    if result["matches"]:
        result["risk"] = "critical" if any(m["ransomware"] for m in result["matches"]) else "high"
    return result

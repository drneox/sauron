"""
Mobile Apps Discovery Module
Finds mobile apps associated with the brand behind a domain on the
Apple App Store (public iTunes Search API) and Google Play (google-play-scraper).
Apps whose developer does not match the brand are flagged as suspicious
(potential brand impersonation).

Optional layers:
  - app_developers: confirmed official developers per store (from the Domain
    row). Their published apps are looked up directly and marked official.
  - LLM verdict: with AI_API_KEY set, a single batch call classifies every
    candidate as official|unrelated|suspicious (llm_verdict field).
"""
import concurrent.futures
import json
import logging
import os
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

import httpx
import tldextract

from modules import ai_summary

logger = logging.getLogger(__name__)

ITUNES_SEARCH_URL = "https://itunes.apple.com/search"
ITUNES_LOOKUP_URL = "https://itunes.apple.com/lookup"
SEARCH_LIMIT = 25
# Detail lookups on Google Play are one HTTP request per app; bound the cost.
GPLAY_DETAIL_LIMIT = 15


def _brand_of(domain: str) -> str:
    return tldextract.extract(domain).domain or domain


_ES_COUNTRIES = {"es", "mx", "ar", "bo", "cl", "co", "pe", "uy", "py", "ve", "ec", "pe",
                 "gt", "cr", "pa", "do", "hn", "sv", "ni", "cu", "pr"}


def _play_locale(domain: str) -> dict[str, str]:
    """Store locale for Google Play: country inferred from the ccTLD
    (bcp.com.bo → bo), language Spanish for LatAm/Spain, else en/us."""
    suffix = (tldextract.extract(domain).suffix or "").lower()
    cc = suffix.split(".")[-1] if suffix else ""
    if len(cc) != 2:
        cc = "us"
    lang = "es" if cc in _ES_COUNTRIES else "en"
    return {"lang": lang, "country": cc}


def _normalize(text: str) -> str:
    # Fold accents first: stores return "Banco de Crédito" and "Banco de Credito"
    # for the same developer, and dropping "é" as punctuation made them differ.
    folded = "".join(c for c in unicodedata.normalize("NFKD", text or "") if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", folded.lower())


def _matches_brand(developer: str, brand: str) -> bool:
    """Fuzzy, case-insensitive containment in either direction, ignoring
    punctuation/spaces (e.g. 'Apple Inc.' matches brand 'apple')."""
    dev_norm = _normalize(developer)
    brand_norm = _normalize(brand)
    if not dev_norm or not brand_norm:
        return False
    return brand_norm in dev_norm or dev_norm in brand_norm


def _apple_entry(item: dict) -> dict:
    return {
        "name": item.get("trackName") or "",
        "store": "app_store",
        "os": "ios",
        "version": item.get("version"),
        "developer": item.get("sellerName") or item.get("artistName") or "",
        "url": item.get("trackViewUrl"),
        "updated": item.get("currentVersionReleaseDate"),
    }


def _search_apple(brand: str, ai_available: bool = True) -> tuple[list[dict], list[dict]]:
    """Returns (apps, suspicious) from the iTunes Search API."""
    apps: list[dict] = []
    suspicious: list[dict] = []
    resp = httpx.get(
        ITUNES_SEARCH_URL,
        params={"term": brand, "entity": "software", "limit": SEARCH_LIMIT},
        timeout=15,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
    )
    resp.raise_for_status()
    for item in resp.json().get("results", []):
        developer = item.get("sellerName") or item.get("artistName") or ""
        entry = _apple_entry(item)
        if not entry["name"]:
            continue
        if _matches_brand(developer, brand):
            apps.append(entry)
        elif ai_available or _matches_brand(entry["name"], brand):
            # With AI the LLM classifies every hit (unrelated ones are dropped
            # at persistence). Without AI, require a brand match in the app
            # name as the poor-man's classifier — store noise (Google Maps,
            # Instagram) never enters the inventory.
            suspicious.append(entry)
    return apps, suspicious


def _play_search_html_ids(query: str) -> dict[str, str]:
    """Fallback: the first Play search hit is often an ad card without appId.
    Scrape the search HTML page and map normalized title -> appId."""
    from modules.common import fetch
    out: dict[str, str] = {}
    try:
        r = fetch(f"https://play.google.com/store/search?q={query}&c=apps", max_bytes=2_000_000)
        ids = list(dict.fromkeys(re.findall(r"/store/apps/details\?id=([a-zA-Z0-9._]+)", r.text)))
        for app_id in ids[:SEARCH_LIMIT]:
            out[app_id] = app_id  # resolved later by detail fetch; keyed for order
    except Exception as e:
        logger.warning(f"[mobile_apps] Play HTML search fallback failed for '{query}': {e}")
    return out


def _search_google_play(brand: str, locale: dict[str, str] | None = None, ai_available: bool = True) -> tuple[list[dict], list[dict]]:
    """Returns (apps, suspicious) from Google Play via google-play-scraper.
    Raises if the library or the store is unavailable — caller tolerates it."""
    from google_play_scraper import app as gplay_app
    from google_play_scraper import search as gplay_search

    loc = locale or {"lang": "en", "country": "us"}
    apps: list[dict] = []
    suspicious: list[dict] = []
    hits = gplay_search(brand, n_hits=SEARCH_LIMIT, **loc)
    scraper_ids = [h.get("appId") for h in hits if h.get("appId")]
    # The store's HTML search page carries the true organic ranking (the top
    # hit often comes as an ad card without appId in the scraper). HTML ids
    # go first so the cap never cuts the most relevant result.
    html_ids = [i for i in _play_search_html_ids(brand).keys()]
    app_ids = html_ids + [i for i in scraper_ids if i not in html_ids]
    def _fetch_detail(app_id: str) -> dict | None:
        try:
            return gplay_app(app_id, **loc)
        except Exception as e:
            logger.warning(f"[mobile_apps] Google Play detail fetch failed for {app_id}: {e}")
            return None

    # One HTTP round-trip per app: fetching them one by one took ~25s for a
    # full result page. Parallel, order preserved (ranking decides the cap).
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        details = list(pool.map(_fetch_detail, app_ids[:GPLAY_DETAIL_LIMIT]))
    for detail in details:
        if not detail:
            continue
        developer = detail.get("developer") or ""
        updated = detail.get("updated")
        if isinstance(updated, (int, float)):
            updated = datetime.fromtimestamp(updated, tz=timezone.utc).date().isoformat()
        entry = {
            "name": detail.get("title") or "",
            "store": "google_play",
            "os": "android",
            "version": detail.get("version"),
            "developer": developer,
            "url": detail.get("url"),
            "updated": updated,
        }
        if not entry["name"]:
            continue
        # Same rule as Apple: with AI every hit goes to the LLM; without it,
        # require a brand match in developer or app name.
        if _matches_brand(developer, brand):
            apps.append(entry)
        elif ai_available or _matches_brand(entry["name"], brand):
            suspicious.append(entry)
    return apps, suspicious


def _lookup_apple_developer(name: str, artist_id: str | None) -> list[dict]:
    """Apps published by a confirmed App Store developer. With artist_id the
    iTunes Lookup API returns their catalog directly; otherwise we search by
    the developer name and keep only results whose seller/artist matches."""
    entries: list[dict] = []
    if artist_id:
        resp = httpx.get(
            ITUNES_LOOKUP_URL,
            params={"id": artist_id, "entity": "software", "limit": SEARCH_LIMIT},
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
        )
        resp.raise_for_status()
        items = resp.json().get("results", [])
    else:
        resp = httpx.get(
            ITUNES_SEARCH_URL,
            params={"term": name, "entity": "software", "limit": SEARCH_LIMIT},
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
        )
        resp.raise_for_status()
        items = [
            item for item in resp.json().get("results", [])
            if _matches_brand(item.get("sellerName") or item.get("artistName") or "", name)
        ]
    for item in items:
        entry = _apple_entry(item)
        if entry["name"]:
            entries.append(entry)
    return entries


def _play_developer_page_ids(name: str) -> list[str]:
    """Google Play has no developer-catalog API, but the public developer page
    lists every app they publish. Scrape it for appIds (authoritative catalog,
    unlike text search which is ranking/ad-biased)."""
    from modules.common import fetch
    for path in ("/store/apps/developer", "/store/apps/dev"):
        url = str(httpx.URL(f"https://play.google.com{path}", params={"id": name}))
        try:
            r = fetch(url, max_bytes=3_000_000)
            ids = list(dict.fromkeys(re.findall(r"/store/apps/details\?id=([a-zA-Z0-9._]+)", r.text)))
            if ids:
                return ids
        except Exception as e:
            logger.warning(f"[mobile_apps] Play developer page failed for '{name}' ({url}): {e}")
    return []


def _search_google_play_developer(name: str, locale: dict[str, str] | None = None) -> list[dict]:
    """Apps published by a confirmed Google Play developer. Primary source: the
    developer's public Play page (true catalog). Fallback: text search by
    developer name, keeping only hits whose developer matches."""
    from google_play_scraper import app as gplay_app
    from google_play_scraper import search as gplay_search

    loc = locale or {"lang": "en", "country": "us"}
    entries: list[dict] = []

    def _detail(app_id: str, authoritative: bool) -> dict | None:
        try:
            detail = gplay_app(app_id, **loc)
        except Exception as e:
            logger.warning(f"[mobile_apps] Google Play detail fetch failed for {app_id}: {e}")
            return None
        developer = detail.get("developer") or ""
        if not authoritative and not _matches_brand(developer, name):
            return None
        updated = detail.get("updated")
        if isinstance(updated, (int, float)):
            updated = datetime.fromtimestamp(updated, tz=timezone.utc).date().isoformat()
        entry = {
            "name": detail.get("title") or "",
            "store": "google_play",
            "os": "android",
            "version": detail.get("version"),
            "developer": developer,
            "url": detail.get("url"),
            "updated": updated,
        }
        return entry if entry["name"] else None

    page_ids = _play_developer_page_ids(name)
    for app_id in page_ids[:SEARCH_LIMIT]:
        entry = _detail(app_id, authoritative=True)
        if entry:
            entries.append(entry)
    if entries:
        return entries

    for hit in gplay_search(name, n_hits=SEARCH_LIMIT, **loc)[:GPLAY_DETAIL_LIMIT]:
        app_id = hit.get("appId")
        if not app_id:
            continue
        entry = _detail(app_id, authoritative=False)
        if entry:
            entries.append(entry)
    return entries


_LLM_VERDICTS = ("official", "unrelated", "suspicious")

_LLM_SYSTEM_PROMPT = (
    "Eres un analista de seguridad experto en suplantación de marca. Recibes el "
    "dominio de una empresa (y a veces su nombre legal) y una lista de apps móviles "
    "encontradas en las tiendas oficiales (App Store / Google Play) al buscar por la marca. "
    "OJO: la marca puede colisionar con empresas NO relacionadas que comparten la "
    "palabra (ej. 'Banco del Pacífico' de Ecuador NO es 'Pacífico Seguros' de Perú; "
    "'Sunrise UPC' suiza NO es la universidad UPC de Perú). Usa el nombre legal si lo "
    "tienes y tu conocimiento del país/sector del dominio para distinguirlas. Para cada "
    "app decide un veredicto:\n"
    '- "official": la app pertenece claramente a la empresa (developer coincide con '
    "la empresa o sus filiales conocidas, o es una app ampliamente conocida de esa marca "
    "en su país/sector).\n"
    '- "unrelated": app legítima de un tercero sin relación con la marca ni intento '
    "de suplantación (colisión de nombre, mismo término genérico, otra empresa con "
    "nombre parecido en otro país/sector).\n"
    '- "suspicious": posible suplantación: usa el nombre de la marca pero el developer '
    "no tiene relación aparente con la empresa.\n"
    "Responde ÚNICAMENTE con un objeto JSON válido con esta forma exacta:\n"
    '{"verdicts": [{"id": <entero id de la app>, "verdict": "official"|"unrelated"|"suspicious"}, ...]}\n'
    "Incluye un veredicto para TODAS las apps de la entrada. No incluyas texto fuera del JSON."
)


def _llm_classify_apps(domain: str, brand: str, candidates: list[dict]) -> dict[tuple[str, str], str]:
    """One batch LLM call classifying every candidate app. Returns
    {(store, name): verdict}; empty dict when AI is not configured or the call
    fails — classification must never break the module."""
    api_key = os.getenv("AI_API_KEY", "").strip()
    if not api_key or not candidates:
        return {}
    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    payload_apps = [
        {"id": idx, "name": a.get("name"), "developer": a.get("developer"), "store": a.get("store")}
        for idx, a in enumerate(candidates)
    ]
    try:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(
                    {"dominio_empresa": domain, "marca": brand, "apps": payload_apps},
                    ensure_ascii=False,
                )},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        with httpx.Client(timeout=ai_summary.TIMEOUT) as client:
            data = ai_summary._chat_request(client, base_url, api_key, payload)
        parsed = json.loads(data["choices"][0]["message"]["content"])
        verdicts: dict[tuple[str, str], str] = {}
        for item in parsed.get("verdicts", []):
            if not isinstance(item, dict):
                continue
            idx, verdict = item.get("id"), item.get("verdict")
            if isinstance(idx, int) and 0 <= idx < len(candidates) and verdict in _LLM_VERDICTS:
                app = candidates[idx]
                verdicts[(app["store"], app["name"])] = verdict
        return verdicts
    except Exception as e:
        logger.warning(f"[mobile_apps] LLM classification failed for '{brand}': {e}")
        return {}


def run(domain: str, app_developers: list[dict] | None = None) -> dict[str, Any]:
    brand = _brand_of(domain)
    locale = _play_locale(domain)
    result: dict[str, Any] = {
        "status": "ok",
        "brand": brand,
        "apps": [],
        "suspicious": [],
        "risk": "low",
        "findings": [],
    }
    errors: list[str] = []
    ai_available = bool(os.getenv("AI_API_KEY", "").strip())

    try:
        apps, suspicious = _search_apple(brand, ai_available)
        result["apps"].extend(apps)
        result["suspicious"].extend(suspicious)
    except Exception as e:
        logger.error(f"[mobile_apps] Apple App Store search failed for '{brand}': {e}")
        errors.append(f"app_store: {e}")

    try:
        apps, suspicious = _search_google_play(brand, locale, ai_available)
        result["apps"].extend(apps)
        result["suspicious"].extend(suspicious)
    except Exception as e:
        logger.warning(f"[mobile_apps] Google Play search unavailable for '{brand}': {e}")
        errors.append(f"google_play: {e}")

    # Confirmed official developers (per-domain setting): look up their catalog
    # directly and merge into the official list. A developer confirmed on one
    # store is searched on the OTHER store too: companies publish under the same
    # legal name on both (BCP's Yape), but the generic brand search only finds
    # apps whose title carries the brand.
    lookups: list[tuple[str, str, str | None]] = []
    seen_lookups: set[tuple[str, str]] = set()
    for dev in app_developers or []:
        store, name = dev.get("store"), dev.get("name")
        if not store or not name:
            continue
        other = "google_play" if store == "app_store" else "app_store"
        for st, artist_id in ((store, dev.get("artist_id")), (other, None)):
            if st not in ("app_store", "google_play") or (st, _normalize(name)) in seen_lookups:
                continue
            seen_lookups.add((st, _normalize(name)))
            lookups.append((st, name, artist_id))

    seen_apps = {(a["store"], a["name"]) for a in result["apps"]}
    for store, name, artist_id in lookups:
        try:
            if store == "app_store":
                official = _lookup_apple_developer(name, artist_id)
            else:
                official = _search_google_play_developer(name, locale)
        except Exception as e:
            logger.warning(f"[mobile_apps] developer lookup failed for '{name}' ({store}): {e}")
            continue
        for entry in official:
            key = (entry["store"], entry["name"])
            if key in seen_apps:
                continue
            seen_apps.add(key)
            entry["official_developer"] = True
            result["apps"].append(entry)

    # Any app whose developer is a confirmed one is official, however it was
    # found. Without this the flag depended on whether the generic search had
    # already returned the app (the developer lookup skips known apps), so the
    # "monitored" check flickered between scans.
    def by_confirmed_developer(entry: dict) -> bool:
        return any(
            entry["store"] == st and _matches_brand(entry.get("developer") or "", nm)
            for st, nm, _ in lookups
        )

    for entry in result["apps"]:
        if by_confirmed_developer(entry):
            entry["official_developer"] = True
    # Suspicious hits published by a confirmed developer are not impersonation:
    # they are the company's own apps (same rule, now also for the official list).
    still_suspicious = []
    for entry in result["suspicious"]:
        if by_confirmed_developer(entry):
            entry["official_developer"] = True
            if (entry["store"], entry["name"]) not in seen_apps:
                seen_apps.add((entry["store"], entry["name"]))
                result["apps"].append(entry)
        else:
            still_suspicious.append(entry)
    result["suspicious"] = still_suspicious

    # Optional LLM layer: one batch verdict per candidate. llm_verdict stays
    # null when AI is not configured or the call fails.
    candidates = result["apps"] + result["suspicious"]
    # Apps from a confirmed developer are official by definition: keep them out of
    # the LLM batch (a shorter prompt answers faster and times out far less).
    to_classify = [a for a in candidates if not a.get("official_developer")]
    verdicts = _llm_classify_apps(domain, brand, to_classify)
    for app_entry in candidates:
        if app_entry.get("official_developer"):
            app_entry["llm_verdict"] = "official"
        else:
            app_entry["llm_verdict"] = verdicts.get((app_entry["store"], app_entry["name"]))
        app_entry.setdefault("official_developer", False)

    # Impersonation needs evidence, not just a store hit. An app is reported only
    # when the brand name appears in ITS OWN name (that is what impersonating a
    # brand means) and the developer is unrelated to the company:
    #   - confirmed:  the LLM also judged it "suspicious"           -> medium
    #   - unverified: no verdict (AI unavailable/failed), name match only -> info
    # "unrelated" apps (name collisions) are dropped everywhere; "official" ones
    # published under another developer (subsidiaries) move to the official list.
    brand_norm = _normalize(brand)

    def name_has_brand(entry: dict) -> bool:
        return bool(brand_norm) and brand_norm in _normalize(entry.get("name") or "")

    if not verdicts and ai_available and to_classify:
        logger.warning(f"[mobile_apps] LLM unavailable for '{brand}' — impersonation findings left unverified")

    confirmed: list[dict] = []
    unverified: list[dict] = []
    for entry in result["suspicious"]:
        verdict = entry.get("llm_verdict")
        if verdict == "unrelated":
            continue
        if verdict == "official":
            result["apps"].append(entry)
            continue
        if not name_has_brand(entry):
            continue
        if verdict == "suspicious":
            entry["impersonation"] = "confirmed"
            confirmed.append(entry)
        elif verdict is None:
            entry["impersonation"] = "unverified"
            unverified.append(entry)
    result["suspicious"] = confirmed + unverified

    # A third-party app that merely shares a word with the brand is not the
    # company's asset (e.g. "Banco del Pacífico" != "Pacífico Seguros").
    if verdicts:
        result["apps"] = [a for a in result["apps"] if a.get("llm_verdict") != "unrelated"]

    if not result["apps"] and not result["suspicious"] and len(errors) == 2:
        result["status"] = "error"
        result["error"] = "; ".join(errors)

    seen = set()
    for entry in result["suspicious"]:
        key = (entry["store"], entry["name"])
        if key in seen:
            continue
        seen.add(key)
        link = f" — {entry['url']}" if entry.get("url") else ""
        if entry["impersonation"] == "confirmed":
            result["findings"].append(
                f"Possible brand impersonation: {entry['store']} app '{entry['name']}' by "
                f"'{entry['developer']}' uses the brand '{brand}' in its name and the developer "
                f"is unrelated to the company (AI-verified){link}"
            )
        else:
            result["findings"].append(
                f"Unverified: {entry['store']} app '{entry['name']}' by '{entry['developer']}' "
                f"uses the brand '{brand}' in its name; AI verification was unavailable, "
                f"review manually{link}"
            )

    result["risk"] = "medium" if confirmed else "low"

    return result

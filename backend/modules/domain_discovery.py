"""
Domain Discovery Module
Finds candidate domains for a company name using:
  1. crt.sh certificate transparency search by organization (O=)
  2. grep.app public code search for brand mentions
  3. Brand permutations across common TLDs, verified via DNS + HTTP
     (redirects to a brand-matching final domain upgrade confidence)
  4. LLM domain brainstorm (only when AI_API_KEY is set): the model proposes
     candidate domains, DNS/HTTP verification decides — nothing appears
     without technical proof. Domains the model knows from training carry
     known=true and upgrade to high confidence once verified.

Attribution upgrade for ALL sources: when a candidate serves HTTPS and its
TLS certificate organization (O=) contains the brand, confidence goes high.
"""
import asyncio
import json
import logging
import os
import re
import socket
import ssl
import unicodedata
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import httpx
import tldextract
from cryptography import x509
from cryptography.x509.oid import NameOID

from modules.ai_summary import _chat_request, _endpoint_and_headers
from modules.discovery_sources import grepapp_hosts

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"
USER_AGENT = "Mozilla/5.0 (compatible; DumbAuditor/1.0)"

CRT_SH_CAP = 40          # max base domains taken from crt.sh
PERMUTATION_CAP = 30     # max generated permutation candidates
STAGE_BUDGET_S = 25      # slow external sources (crt.sh, LLM) can't hold discovery past this
LLM_BRAINSTORM_CAP = 25  # max domains requested from the LLM
LLM_TIMEOUT = 45         # seconds for the single brainstorm call
TOTAL_CAP = 50           # max candidates returned overall

PERMUTATION_TLDS = ["com", "net", "org", "io", "co", "app", "dev", "cloud", "pe", "com.pe"]

# Offline extractor: uses the suffix snapshot bundled with tldextract
# (no network fetch of the public suffix list).
_extract = tldextract.TLDExtract(suffix_list_urls=())

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def _strip_accents(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _normalize(text: str) -> str:
    return _strip_accents(text.lower())


def _registrable_domain(host: str) -> str | None:
    ext = _extract(host)
    domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    return domain or None


def _brand_variants(company_name: str) -> list[str]:
    """Brand spelling variants used for permutations and title matching."""
    base = _normalize(company_name)
    words = re.findall(r"[a-z0-9]+", base)
    variants: set[str] = set()
    if words:
        variants.add("".join(words))               # no spaces
        if len(words) > 1:
            variants.add("-".join(words))          # hyphenated
            # Distinctive words only: "grupo credicorp" must permute "credicorp",
            # never the generic first word "grupo" (grupo.com is someone else's).
            distinctive = [w for w in words if len(w) >= 3 and w not in _GENERIC_BRAND_WORDS]
            if distinctive:
                variants.add(distinctive[0])
                variants.add("".join(distinctive))
            else:
                variants.add(words[0])
    return sorted(variants)


async def _crt_sh_by_org(company_name: str) -> dict[str, dict]:
    """Search crt.sh for certificates whose organization (O=) matches the
    company name. crt.sh's O= query is itself an ILIKE match on the cert
    subject organization, so every hit counts as high confidence (the JSON
    feed does not echo the subject O back per cert). Returns
    {registrable_domain: candidate} dict."""
    candidates: dict[str, dict] = {}
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    CRT_SH_URL,
                    params={"O": company_name, "output": "json"},
                    headers={"User-Agent": USER_AGENT},
                )
                if resp.status_code != 200:
                    # crt.sh is flaky: 429/5xx under load, and occasionally a
                    # spurious 404 that succeeds on retry.
                    if resp.status_code in (404, 429) or resp.status_code >= 500:
                        logger.info(f"[discovery] crt.sh returned {resp.status_code} (attempt {attempt + 1})")
                        if attempt < max_attempts - 1:
                            await asyncio.sleep(3 * (attempt + 1))
                            continue
                    return candidates
                data = resp.json()
                for entry in data:
                    not_before = entry.get("not_before", "")
                    # For O= (organization) queries crt.sh fills name_value
                    # with the matched org identity, while common_name keeps
                    # the real DNS name — so harvest both fields.
                    names = {n.strip().lower() for n in entry.get("name_value", "").split("\n")}
                    cn = entry.get("common_name", "").strip().lower()
                    if cn:
                        names.add(cn)
                    for name in names:
                        if not name or name.startswith("*.") or "." not in name or " " in name:
                            continue
                        base = _registrable_domain(name)
                        if not base or base in candidates:
                            continue
                        candidates[base] = {
                            "domain": base,
                            "source": "crt.sh",
                            "confidence": "high",
                            "evidence": f"Cert O='{company_name}' issued {not_before} (crt.sh)",
                        }
                    if len(candidates) >= CRT_SH_CAP:
                        break
                return dict(list(candidates.items())[:CRT_SH_CAP])
        except Exception as e:
            logger.debug(f"[discovery] crt.sh attempt {attempt + 1} for '{company_name}': {e}")
            if attempt < max_attempts - 1:
                await asyncio.sleep(3 * (attempt + 1))
    return candidates


def _permutation_domains(company_name: str) -> list[str]:
    variants = _brand_variants(company_name)
    domains: list[str] = []
    for variant in variants:
        for tld in PERMUTATION_TLDS:
            domains.append(f"{variant}.{tld}")
            if len(domains) >= PERMUTATION_CAP:
                return domains
    return domains


_LLM_SYSTEM_PROMPT = (
    "Eres un analista ASM (Attack Surface Management) especializado en descubrimiento "
    "de activos. Dado el nombre de una empresa, propones dominios que la empresa podría "
    "poseer o usar. Respondes ÚNICAMENTE con JSON válido, sin texto adicional."
)

_LLM_USER_TEMPLATE = (
    'Empresa: "{company_name}"\n'
    "Genera hasta {cap} dominios candidatos que esta empresa podría poseer o usar:\n"
    "- su dominio oficial más probable,\n"
    "- variaciones de marca (con y sin guiones, abreviaturas, siglas),\n"
    "- el ccTLD del país de la empresa y TLDs comunes (.com, .net, .org, .io...),\n"
    "- dominios de productos o servicios conocidos de su sector,\n"
    "- dominios que CONOZCAS de la empresa por tu entrenamiento (márcalos known: true).\n"
    "Devuelve ÚNICAMENTE un array JSON con esta forma exacta:\n"
    '[{{"domain": "ejemplo.com", "reason": "motivo breve", "known": true}}]\n'
    "Dominios en minúsculas, sin protocolo ni rutas. known: true solo si tienes "
    "certeza por tu entrenamiento de que el dominio pertenece a la empresa."
)


def _parse_llm_domains(content: str) -> list[dict]:
    """Tolerant parse of the brainstorm response: accepts a bare array or an
    object wrapping one, and falls back to extracting the JSON array span."""
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        m = re.search(r"\[.*\]", content, re.DOTALL)
        if not m:
            return []
        try:
            parsed = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    if isinstance(parsed, dict):
        parsed = next((v for v in parsed.values() if isinstance(v, list)), [])
    if not isinstance(parsed, list):
        return []

    out: list[dict] = []
    seen: set[str] = set()
    for item in parsed:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("domain") or "").strip().lower().rstrip(".")
        if not raw or not _DOMAIN_RE.match(raw):
            continue
        base = _registrable_domain(raw)
        if not base or base in seen:
            continue
        seen.add(base)
        out.append({
            "domain": base,
            "reason": str(item.get("reason") or "")[:200],
            "known": bool(item.get("known")),
        })
        if len(out) >= LLM_BRAINSTORM_CAP:
            break
    return out


async def llm_brainstorm_domains(company_name: str) -> list[dict]:
    """LLM-proposed candidate domains for a company name ("el LLM propone,
    el DNS dispone"). Requires AI_API_KEY — returns an empty list silently
    without it. A single chat call (45s timeout); never raises."""
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        return []
    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _LLM_SYSTEM_PROMPT},
            {"role": "user", "content": _LLM_USER_TEMPLATE.format(
                company_name=company_name, cap=LLM_BRAINSTORM_CAP)},
        ],
        "temperature": 0.4,
    }
    try:
        def _call() -> dict:
            with httpx.Client(timeout=LLM_TIMEOUT) as client:
                return _chat_request(client, base_url, api_key, payload)

        data = await asyncio.to_thread(_call)
        content = data["choices"][0]["message"]["content"]
        return _parse_llm_domains(content)
    except Exception as e:
        logger.info(f"[discovery] LLM brainstorm failed for '{company_name}': {e}")
        return []


def _add_candidate(candidates: dict[str, dict], cand: dict) -> None:
    """Merge-insert a candidate: the same domain found by several sources is
    fused into one entry — highest confidence wins, `source` keeps the primary
    (highest-confidence) origin and `sources` lists every source."""
    cand.setdefault("sources", [cand["source"]])
    existing = candidates.get(cand["domain"])
    if existing is None:
        candidates[cand["domain"]] = cand
        return
    for src in cand["sources"]:
        if src not in existing["sources"]:
            existing["sources"].append(src)
    if _CONFIDENCE_ORDER.get(cand["confidence"], 3) < _CONFIDENCE_ORDER.get(existing["confidence"], 3):
        existing["confidence"] = cand["confidence"]
        existing["source"] = cand["source"]
    if cand["evidence"] not in existing["evidence"]:
        existing["evidence"] += f" | {cand['evidence']}"
    if cand.get("source_detail") and not existing.get("source_detail"):
        existing["source_detail"] = cand["source_detail"]
    if cand.get("known"):
        existing["known"] = True


async def _resolves(domain: str, semaphore: asyncio.Semaphore) -> bool:
    # gethostbyname has no timeout of its own: a name whose lookup gets dropped
    # (some TLDs) blocked ~10s each, gating whole discovery batches. Bounded here.
    async with semaphore:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 4
            await resolver.resolve(domain, "A")
            return True
        except Exception:
            return False


async def _filter_resolving(domains: list[str]) -> set[str]:
    semaphore = asyncio.Semaphore(20)
    results = await asyncio.gather(*(_resolves(d, semaphore) for d in domains))
    return {d for d, ok in zip(domains, results) if ok}


def _extract_title(html: str) -> str | None:
    m = TITLE_RE.search(html[:100_000])
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


def _brand_in_title(title: str, variants: list[str]) -> bool:
    title_norm = _normalize(title)
    title_compact = re.sub(r"[^a-z0-9]", "", title_norm)
    return any(v.replace("-", "") in title_compact or v in title_norm for v in variants)


async def _probe_http(client: httpx.AsyncClient, domain: str, semaphore: asyncio.Semaphore) -> tuple[int | None, str | None, str | None]:
    async with semaphore:
        try:
            resp = await client.get(f"https://{domain}", headers={"User-Agent": USER_AGENT})
            return resp.status_code, _extract_title(resp.text), str(resp.url)
        except Exception as e:
            logger.debug(f"[discovery] probe https://{domain}: {e}")
            return None, None, None


def _cert_organization(domain: str) -> str | None:
    """Organization (O=) from the TLS certificate served on :443, or None.
    Verification is disabled on purpose (cert may be self-signed/expired —
    we only read the subject), so the DER cert is parsed manually."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return None
        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return attrs[0].value if attrs else None
    except Exception as e:
        logger.debug(f"[discovery] cert O= for {domain}: {e}")
        return None


async def _cert_organizations(domains: list[str]) -> list[str | None]:
    semaphore = asyncio.Semaphore(10)

    async def _one(domain: str) -> str | None:
        async with semaphore:
            return await asyncio.to_thread(_cert_organization, domain)

    return await asyncio.gather(*(_one(d) for d in domains))


async def _grepapp_by_brand(company_name: str, variants: list[str], cap: int = 10) -> dict[str, dict]:
    """Brand mentions in public code (grep.app) yield candidate hosts; keep
    only registrable domains containing a brand variant."""
    candidates: dict[str, dict] = {}
    hosts = await grepapp_hosts(company_name)
    compact_variants = [v.replace("-", "") for v in variants]
    for host in sorted(hosts):
        base = _registrable_domain(host)
        if not base or base in candidates:
            continue
        base_compact = re.sub(r"[^a-z0-9]", "", _normalize(base))
        if not any(v in base_compact for v in compact_variants):
            continue
        candidates[base] = {
            "domain": base,
            "source": "grep.app",
            "confidence": "medium",
            "evidence": f"Host '{host}' mentions '{company_name}' in public code (grep.app)",
        }
        if len(candidates) >= cap:
            break
    return candidates


async def run(company_name: str) -> list[dict[str, Any]]:
    """Discover candidate domains for a company name. Never raises:
    each stage is isolated so a crt.sh outage still yields permutations
    (and vice versa)."""
    company_name = company_name.strip()
    candidates: dict[str, dict] = {}

    # Stages 1-4 are independent network lookups: run them concurrently and merge
    # in a fixed order (crt.sh, grep.app, permutations, LLM) so the result stays
    # deterministic. Each stage is isolated so one outage never sinks the rest.
    async def stage_crt() -> list[dict]:
        try:
            found = list((await asyncio.wait_for(_crt_sh_by_org(company_name), STAGE_BUDGET_S)).values())
            logger.info(f"[discovery] crt.sh gave {len(found)} base domains for '{company_name}'")
            return found
        except Exception as e:
            logger.error(f"[discovery] crt.sh stage failed for '{company_name}': {e or type(e).__name__}")
            return []

    async def stage_grepapp() -> list[dict]:
        try:
            found = list((await _grepapp_by_brand(company_name, _brand_variants(company_name))).values())
            logger.info(f"[discovery] grep.app gave {len(found)} base domains for '{company_name}'")
            return found
        except Exception as e:
            logger.error(f"[discovery] grep.app stage failed for '{company_name}': {e}")
            return []

    async def stage_permutations() -> list[dict]:
        try:
            permutations = _permutation_domains(company_name)
            resolving_perms = await _filter_resolving(permutations)
            logger.info(f"[discovery] {len(resolving_perms)}/{len(permutations)} permutations resolve for '{company_name}'")
            return [{
                "domain": domain,
                "source": "permutation",
                "confidence": "low",
                "evidence": f"Brand permutation of '{company_name}'; resolves via DNS",
            } for domain in sorted(resolving_perms)]
        except Exception as e:
            logger.error(f"[discovery] permutation stage failed for '{company_name}': {e}")
            return []

    async def stage_llm() -> list[dict]:
        # Only with AI_API_KEY; only domains that resolve enter — verification
        # later decides the final confidence.
        try:
            llm_cands = await asyncio.wait_for(llm_brainstorm_domains(company_name), STAGE_BUDGET_S)
            resolving_llm = await _filter_resolving([c["domain"] for c in llm_cands])
            kept = [{
                "domain": c["domain"],
                "source": "llm",
                "source_detail": c["reason"],
                "known": c["known"],
                "confidence": "low",  # provisional — upgraded in verification
                "evidence": f"LLM brainstorm: {c['reason']}",
            } for c in llm_cands if c["domain"] in resolving_llm]
            if llm_cands:
                logger.info(f"[discovery] LLM proposed {len(llm_cands)} domains, {len(kept)} resolve for '{company_name}'")
            return kept
        except Exception as e:
            logger.error(f"[discovery] LLM stage failed for '{company_name}': {e or type(e).__name__}")
            return []

    for group in await asyncio.gather(stage_crt(), stage_grepapp(), stage_permutations(), stage_llm()):
        for cand in group:
            _add_candidate(candidates, cand)

    # Cap total, crt.sh (high confidence) first
    ordered = sorted(candidates.values(), key=lambda c: _CONFIDENCE_ORDER.get(c["confidence"], 3))
    candidates = {c["domain"]: c for c in ordered[:TOTAL_CAP]}

    # Stage 5: verification — DNS state for crt.sh candidates + HTTP probe
    try:
        dns_sem = asyncio.Semaphore(20)
        dns_results = await asyncio.gather(
            *(_resolves(d, dns_sem) for d in candidates)
        )
        for (domain, cand), ok in zip(candidates.items(), dns_results):
            cand["resolves"] = ok

        # LLM-only candidates that no longer resolve are discarded — an LLM
        # suggestion without technical proof never appears.
        for domain, cand in list(candidates.items()):
            if not cand["resolves"] and set(cand["sources"]) == {"llm"}:
                del candidates[domain]

        variants = _brand_variants(company_name)
        compact_variants = [v.replace("-", "") for v in variants]
        http_sem = asyncio.Semaphore(10)
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
            probe_results = await asyncio.gather(
                *(_probe_http(client, d, http_sem) if c["resolves"] else asyncio.sleep(0, result=(None, None, None))
                  for d, c in candidates.items())
            )
        for cand, (status, title, final_url) in zip(candidates.values(), probe_results):
            cand["http_status"] = status
            heuristic_source = any(s in ("permutation", "llm") for s in cand["sources"])
            if not heuristic_source:
                continue
            # Redirect calibration: a candidate that redirects to a domain
            # whose registrable name contains the brand is very likely owned
            # by the company (parked/typo domains usually redirect elsewhere).
            final_host = (urlparse(final_url).hostname or "") if final_url else ""
            final_base = _registrable_domain(final_host) if final_host else None
            if final_base and final_base != cand["domain"]:
                final_compact = re.sub(r"[^a-z0-9]", "", _normalize(final_base))
                if any(v in final_compact for v in compact_variants):
                    cand["confidence"] = "high"
                    cand["evidence"] += f"; redirects to brand domain '{final_base}'"
                    continue
            if title and _brand_in_title(title, variants):
                if _CONFIDENCE_ORDER.get(cand["confidence"], 3) > _CONFIDENCE_ORDER["medium"]:
                    cand["confidence"] = "medium"
                cand["evidence"] += f"; page title: '{title}'"

        # TLS certificate attribution: if the HTTPS cert's organization (O=)
        # contains the brand, upgrade to high — applies to every source.
        https_domains = [d for d, c in candidates.items() if c.get("http_status") is not None]
        if https_domains:
            orgs = await _cert_organizations(https_domains)
            for domain, org in zip(https_domains, orgs):
                if not org:
                    continue
                org_compact = re.sub(r"[^a-z0-9]", "", _normalize(org))
                if any(v in org_compact for v in compact_variants):
                    cand = candidates[domain]
                    cand["confidence"] = "high"
                    if f"Cert O='{org}'" not in cand["evidence"]:
                        cand["evidence"] += f"; Cert O='{org}'"

        # LLM confidence rule: verified (resolves) + known from training → high;
        # verified without known → medium (never below an upgrade already made).
        for cand in candidates.values():
            if "llm" not in cand["sources"] or not cand.get("resolves"):
                continue
            if cand.get("known"):
                cand["confidence"] = "high"
            elif _CONFIDENCE_ORDER.get(cand["confidence"], 3) > _CONFIDENCE_ORDER["medium"]:
                cand["confidence"] = "medium"
    except Exception as e:
        logger.error(f"[discovery] verification stage failed for '{company_name}': {e}")
        for cand in candidates.values():
            cand.setdefault("resolves", cand["source"] == "permutation" or "llm" in cand.get("sources", []))
            cand.setdefault("http_status", None)

    result = sorted(candidates.values(), key=lambda c: _CONFIDENCE_ORDER.get(c["confidence"], 3))
    logger.info(f"[discovery] '{company_name}' -> {len(result)} candidates")
    return result


_GENERIC_BRAND_WORDS = {
    "grupo", "group", "holding", "holdings", "corp", "corporation", "corporacion",
    "company", "compania", "the", "del", "los", "las", "and", "inc", "llc", "ltd",
    "sac", "sas", "sa",
}


def _brand_tokens(company_name: str) -> list[str]:
    """Distinctive words of a company name ('grupo credicorp' -> ['credicorp'])."""
    words = re.findall(r"[a-z0-9]+", unicodedata.normalize("NFKD", company_name.lower())
                       .encode("ascii", "ignore").decode())
    return [w for w in words if len(w) >= 3 and w not in _GENERIC_BRAND_WORDS]


def _app_matches_company(app: dict, tokens: list[str]) -> bool:
    from modules import mobile_apps
    return any(
        mobile_apps._matches_brand(app.get("name") or "", t)
        or mobile_apps._matches_brand(app.get("developer") or "", t)
        for t in tokens
    )


async def discover_apps(company_name: str) -> list[dict[str, Any]]:
    """App-store discovery for a company name — runs alongside domain discovery
    so 'discover' means domains AND mobile apps. Reuses mobile_apps store
    search; only apps carrying a distinctive word of the company are kept.
    Never raises: app discovery is informational at this stage."""
    from modules import mobile_apps

    ai_available = bool(os.getenv("AI_API_KEY", "").strip())
    candidates: list[dict] = []
    try:
        apps, susp = await asyncio.to_thread(mobile_apps._search_apple, company_name, ai_available)
        candidates.extend(apps)
        candidates.extend(susp)
    except Exception as e:
        logger.warning(f"[discovery] Apple app search failed for '{company_name}': {e}")
    try:
        apps, susp = await asyncio.to_thread(mobile_apps._search_google_play, company_name, None, ai_available)
        candidates.extend(apps)
        candidates.extend(susp)
    except Exception as e:
        logger.warning(f"[discovery] Google Play app search failed for '{company_name}': {e}")
    if not candidates:
        return []
    # No LLM here: on the configured model it costs ~3s per app (12 apps ~30s,
    # 38 apps >90s), far too slow for an interactive modal — and it timed out
    # anyway. Distinctive-word matching on name/developer is instant; scans
    # (background) still run the LLM classification.
    tokens = _brand_tokens(company_name) or [company_name]
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for app in candidates:
        key = (app.get("store") or "", app.get("name") or "")
        if key in seen:
            continue
        seen.add(key)
        if not _app_matches_company(app, tokens):
            continue
        app["llm_verdict"] = None
        out.append(app)
    logger.info(f"[discovery] '{company_name}' -> {len(out)} app candidates")
    return out[:20]

# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""
ASM (Attack Surface Management) - FastAPI Backend
Main application entry point
"""
import asyncio
import csv
import hashlib
import io
import json
import logging
import math
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, field_validator

load_dotenv()

# Modules
from modules import pdf_report
from modules import (
    whois_lookup,
    dns_enum,
    subdomain_enum,
    port_scan,
    ssl_check,
    headers_check,
    email_security,
    tech_fingerprint,
    breach_check,
    exposed_files,
    blacklist_check,
    cors_check,
    cookie_security,
    js_secrets,
    secret_verification,
    waf_detect,
    robots_sitemap,
    dnssec_check,
    admin_discovery,
    tls_audit,
    frontend_cve,
    cloud_metadata,
    api_exposure,
    wayback_secrets,
    nuclei_integration,
    subdomain_eval,
    smart_fuzz,
    ai_summary,
    tools_runner,
    agent_scan,
    chat_assistant,
    chat_guardrails,
    domain_discovery,
    mobile_apps,
    reverse_ip,
    notify,
    proxy_pool,
)

from db import AppSetting, Asset, AssetHistory, Company, Domain, Endpoint, Finding, Scan, Schedule, Subdomain, User, close_db, init_db
from modules import compliance
from scan_queue import ScanQueue
from auth import (
    AUTH_ENABLED,
    AuthMiddleware,
    bearer_token,
    current_user,
    hash_legacy_tokens,
    hash_password,
    issue_token,
    require_role,
    resolve_token_user,
    revoke_token,
    revoke_user_tokens,
    user_id_of,
    verify_password,
    ROLES,
    DEV_USER,
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("asm")

# ── In-memory live-progress store ─────────────────────────────────────────────
# Only scans in flight (queued/running) live here; completed scans are persisted
# to the DB and removed from this dict.
SCANS: dict[str, dict] = {}

# Ephemeral store for company-name -> domain discovery jobs (never persisted).
DISCOVERIES: dict[str, dict] = {}

scan_queue = ScanQueue()

# ── Rate limiting (POST /api/scan): 10 requests/minute per IP ─────────────────
RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 60.0
_rate_hits: dict[str, list[float]] = {}

# ── Rate limiting (POST /api/discover): per-IP, env-tunable ──────────────────
DISCOVER_RATE_LIMIT_MAX = int(os.getenv("DISCOVER_RATE_LIMIT_MAX", "30"))
_discover_rate_hits: dict[str, list[float]] = {}

# ── Rate limiting (POST /api/chat): soft, 10 messages/minute per IP ──────────
CHAT_RATE_LIMIT_MAX = 10
_chat_rate_hits: dict[str, list[float]] = {}


def _rate_limit_ok(ip: str) -> bool:
    return _rate_limit_check(ip, _rate_hits, RATE_LIMIT_MAX)


def _discover_rate_limit_ok(ip: str) -> bool:
    return _rate_limit_check(ip, _discover_rate_hits, DISCOVER_RATE_LIMIT_MAX)


def _chat_rate_limit_ok(ip: str) -> bool:
    return _rate_limit_check(ip, _chat_rate_hits, CHAT_RATE_LIMIT_MAX)


def _rate_limit_check(ip: str, hits_store: dict[str, list[float]], max_hits: int) -> bool:
    now = time.time()
    hits = [t for t in hits_store.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
    if len(hits) >= max_hits:
        hits_store[ip] = hits
        return False
    hits.append(now)
    hits_store[ip] = hits
    return True


# ── Lifespan: DB, queue workers, scheduler ─────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    upgraded = await hash_legacy_tokens()
    if upgraded:
        logger.info(f"Migrated {upgraded} legacy plaintext auth token(s) to sha256 at rest")
    interrupted = await Scan.filter(status__in=["queued", "running"]).update(status="interrupted")
    if interrupted:
        logger.info(f"Marked {interrupted} leftover scan(s) as interrupted")
    await scan_queue.start(_run_and_persist_scan)
    scheduler = asyncio.create_task(_scheduler_loop())
    yield
    scheduler.cancel()
    await asyncio.gather(scheduler, return_exceptions=True)
    await scan_queue.stop()
    await close_db()


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Sauron API",
    description="Sauron — attack surface management with AI agent",
    version="1.0.0",
    lifespan=lifespan,
)

# Baseline auth gate (no-op unless AUTH_ENABLED=true). Registered before CORS
# so CORSMiddleware stays outermost and decorates its 401 responses too.
app.add_middleware(AuthMiddleware)

# Edge gate (IP whitelist + HTTP Basic, no-op unless configured). Runs inside
# CORS but BEFORE the Bearer auth middleware.
from edge_gate import EdgeGateMiddleware
app.add_middleware(EdgeGateMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:3000",
                   "http://127.0.0.1:5173", "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _normalize_domain(v: str) -> str:
    v = v.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not DOMAIN_RE.match(v):
        raise ValueError(f"'{v}' is not a valid domain name")
    return v


# ── Models ─────────────────────────────────────────────────────────────────────
def _validate_modules_allowlist(v: list[str] | None, allowed: set[str]) -> list[str] | None:
    if v is None:
        return v
    if not v:
        raise ValueError("modules must not be empty")
    if len(v) > MODULE_SCAN_MAX:
        raise ValueError(f"modules accepts at most {MODULE_SCAN_MAX} entries")
    unknown = sorted(set(v) - allowed)
    if unknown:
        raise ValueError(f"Unknown or non-runnable module(s): {', '.join(unknown)}")
    return v


class ScanRequest(BaseModel):
    domain: str
    company_name: str | None = None
    # None = not specified → falls back to the agent_mode_default setting
    agent_mode: bool | None = None
    # True = vulnerability-only scan: skip pure discovery modules and evaluate
    # the already-inventoried assets as-is. None = use the settings default.
    skip_discovery: bool | None = None
    # Manual module scan: run ONLY these modules (kind="module").
    modules: list[str] | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _normalize_domain(v)

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v: list[str] | None) -> list[str] | None:
        return _validate_modules_allowlist(v, set(MODULE_SCANNABLE))


class AgentScanRequest(BaseModel):
    domain: str
    company_name: str | None = None
    max_steps: int | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _normalize_domain(v)

    @field_validator("max_steps")
    @classmethod
    def validate_max_steps(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("max_steps must be >= 1")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    message: str


class CompanyCreateRequest(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Company name cannot be empty")
        return v


class DomainCreateRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _normalize_domain(v)


class ScheduleRequest(BaseModel):
    # All fields optional: None means "leave unchanged". Clients changing the
    # vuln scan track send interval_hours/enabled/agent_mode; discovery-only
    # updates send just the discover_* fields so per-domain vuln schedules
    # are not clobbered (e.g. company-wide "schedule discovery for all").
    interval_hours: int | None = None
    enabled: bool | None = None
    agent_mode: bool | None = None
    discover_enabled: bool | None = None
    discover_interval_hours: int | None = None

    @field_validator("interval_hours", "discover_interval_hours")
    @classmethod
    def validate_interval(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("interval hours must be >= 1")
        return v


class DiscoverRequest(BaseModel):
    company_name: str

    @field_validator("company_name")
    @classmethod
    def validate_company_name(cls, v: str) -> str:
        v = v.strip()
        if not (2 <= len(v) <= 100):
            raise ValueError("company_name must be between 2 and 100 characters")
        return v


# ── Risk helpers ───────────────────────────────────────────────────────────────
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: RISK_ORDER.get(r, 0))


# ── Finding categories ─────────────────────────────────────────────────────────
# Design principle: surface ≠ vulnerability. Being visible on the internet
# (subdomains enumerated, ports open, technologies detected) is inventory, not
# a security problem. Every aggregated finding carries a `category` and only
# non-info categories may lower the score:
#   vulnerability     — exploitable/confirmed problem (public bucket, valid secret, .env)
#   misconfiguration  — hardening gap (headers, TLS, cookies, risky service)
#   exposure          — notable attack surface, low weight (admin panel reachable, API docs)
#   info              — neutral inventory; NEVER penalizes
FINDING_CATEGORIES = {"vulnerability", "misconfiguration", "exposure", "info"}

# Score weight per category: misconfiguration weighs 60% of a vulnerability,
# exposure 25%, info nothing.
CATEGORY_SCORE_WEIGHT = {"vulnerability": 1.0, "misconfiguration": 0.6, "exposure": 0.25, "info": 0.0}

# Default category of a module's findings (keyed by module name as stored in
# results). Criterion: pure inventory modules are `info`; the module maps to
# the category of the findings it actually emits — e.g. port_scan NEVER emits
# neutral "N open ports" findings (that inventory lives in open_ports/
# total_open), only risky/unauthenticated services, so ports → misconfiguration;
# cloud_metadata only promotes PUBLIC buckets to findings (private existing
# ones stay in existing_private), so cloud_storage → vulnerability.
MODULE_FINDING_CATEGORY: dict[str, str] = {
    # Neutral inventory — never penalizes
    "whois": "info",
    "dns": "info",               # refined per-finding: AXFR allowed is a real misconfiguration
    "subdomains": "info",        # enumeration results, incl. sensitive-looking names
    "tech": "info",              # fingerprinting; cookie flags are also reported by cookies
    "waf": "info",               # "WAF detected" / "No WAF detected" are posture notes
    "reverse_ip": "info",        # co-hosted neighbors
    "mobile_apps": "info",       # refined per-finding: brand impersonation is exposure
    "subdomain_eval": "info",    # refined per-finding: forwarded secrets are vulnerabilities
    # Exposure — notable but cheap
    "robots": "exposure",        # sensitive-path disclosure via robots/sitemap
    "admin": "exposure",         # reachable admin panels / redirects to auth
    "api_exposure": "exposure",  # refined per-finding: off-site mentions are info
    "smart_fuzz": "exposure",    # refined per-finding: critical/high paths are vulnerabilities
    # Misconfiguration — hardening gaps
    "dnssec": "misconfiguration",  # the module only reports DNSSEC failures
    "ssl": "misconfiguration",
    "tls": "misconfiguration",
    "headers": "misconfiguration",
    "cors": "misconfiguration",
    "cookies": "misconfiguration",
    "email": "misconfiguration",
    "ports": "misconfiguration",   # only risky/unauthenticated services reach findings
    # Vulnerability — real problems
    "js_secrets": "vulnerability",
    "secret_verification": "vulnerability",  # refined per-finding: noise notes are info
    "exposed": "vulnerability",
    "breach": "vulnerability",
    "blacklist": "vulnerability",
    "frontend_cve": "vulnerability",
    "nuclei": "vulnerability",
    "wayback": "vulnerability",
    "cloud_storage": "vulnerability",  # only public buckets reach findings
    "agent": "vulnerability",          # agent-confirmed issues
}

# Per-finding refinements for mixed modules. Each rule receives the raw finding
# (usually a string) and returns a category that overrides the module default.
def _dns_finding_category(finding) -> str:
    # Zone transfer exposes the whole DNS zone — a real misconfiguration;
    # everything else dns_enum reports is neutral inventory.
    return "misconfiguration" if "zone transfer" in str(finding).lower() else "info"


def _smart_fuzz_finding_category(finding) -> str:
    s = str(finding)
    if s.startswith(("[CRITICAL]", "[HIGH]")):
        return "vulnerability"   # sensitive path confirmed reachable (e.g. /.git)
    if s.startswith("[INFO]"):
        return "info"            # scanner-side notes (WAF blocking, etc.)
    return "exposure"


def _secret_verification_finding_category(finding) -> str:
    s = str(finding).lower()
    if "verified as valid" in s or s.startswith("jwt issue"):
        return "vulnerability"
    # rejected / inconclusive / nothing-to-verify notes are scanner noise
    return "info"


def _api_exposure_finding_category(finding) -> str:
    s = str(finding)
    if s.startswith(("GitHub repository", "GitHub code file", "Postman public workspace")):
        return "info"            # off-site brand mentions, neutral
    if s.startswith("Postman public collection") and "internal-looking" not in s:
        return "info"
    return "exposure"


def _mobile_apps_finding_category(finding) -> str:
    return "exposure" if "impersonation" in str(finding).lower() else "info"


def _subdomain_eval_finding_category(finding) -> str:
    s = str(finding).lower()
    if "secret" in s:
        return "vulnerability"   # forwarded js_secrets / secret-verification hits
    if "evaluated as" in s:
        return "info"            # "new subdomain evaluated as X risk" notice
    return "misconfiguration"    # forwarded headers/tech findings from the live host


def _breach_finding_category(finding) -> str:
    s = str(finding).lower()
    if "skipped" in s or "not configured" in s:
        return "info"            # scanner notes (e.g. "HIBP_API_KEY not configured")
    if "email address(es) discovered" in s:
        return "info"            # crt.sh-style email inventory
    if "hunter.io" in s:
        return "exposure"        # publicly enumerable emails
    return "vulnerability"       # actual breaches / leaked combos / leaked records


FINDING_CATEGORY_RULES = {
    "dns": _dns_finding_category,
    "smart_fuzz": _smart_fuzz_finding_category,
    "secret_verification": _secret_verification_finding_category,
    "api_exposure": _api_exposure_finding_category,
    "mobile_apps": _mobile_apps_finding_category,
    "subdomain_eval": _subdomain_eval_finding_category,
    "breach": _breach_finding_category,
}

# Unknown modules default to info: an unrecognized module must never tank the
# score by accident.
DEFAULT_FINDING_CATEGORY = "info"


def _finding_category(module_name: str, finding) -> str:
    """Category of one finding: an explicit `category` on a dict finding wins,
    then a per-finding rule, then the module default."""
    if isinstance(finding, dict):
        own = finding.get("category")
        if own in FINDING_CATEGORIES:
            return own
    rule = FINDING_CATEGORY_RULES.get(module_name)
    if rule is not None:
        try:
            cat = rule(finding)
        except Exception:
            cat = None
        if cat in FINDING_CATEGORIES:
            return cat
    return MODULE_FINDING_CATEGORY.get(module_name, DEFAULT_FINDING_CATEGORY)


def _overall_score(results: dict) -> dict:
    """Compute a global risk score (0-100) and grade (A-F).

    Category-aware model: findings and module risks are weighted by their
    finding category (vulnerability 100%, misconfiguration 60%, exposure 25%)
    and `info` (neutral inventory: subdomains, open ports, technologies…)
    never penalizes. A domain with only inventory scores 100/A regardless of
    how large its attack surface is.
    """
    module_names = [
        "whois", "dns", "subdomains", "ports", "ssl", "headers", "email",
        "tech", "breach", "exposed", "blacklist", "cors", "cookies",
        "js_secrets", "secret_verification", "waf", "robots", "dnssec",
        "admin", "tls", "frontend_cve", "cloud_storage", "api_exposure",
        "wayback", "nuclei", "mobile_apps", "reverse_ip", "subdomain_eval",
        "smart_fuzz",
    ]
    weights = {"low": 0, "medium": 25, "high": 60, "critical": 100}
    module_risks = [results.get(name, {}).get("risk", "low") for name in module_names]
    # Base: module risks scaled by the module's category weight; info modules
    # contribute 0. The denominator stays the full module list so the scale is
    # comparable with the pre-category model. Tolerate unknown/extended risk
    # levels from modules (e.g. "info") — an exotic value must never crash the
    # aggregation of the other 28.
    avg = sum(
        weights.get(r, 0) * CATEGORY_SCORE_WEIGHT.get(MODULE_FINDING_CATEGORY.get(name, DEFAULT_FINDING_CATEGORY), 0.0)
        for name, r in zip(module_names, module_risks)
    ) / len(module_risks)
    base = 100 - avg

    # Xpanse-style severity model: penalties come from actual findings with
    # diminishing returns per severity class (repeated mediums don't stack to
    # infinity), and a hard cap keeps the letter and the risk badge coherent:
    # any critical finding caps the grade at D; highs cap at C. Only non-info
    # findings count — raw counts drive the caps, category-weighted counts
    # drive the penalty (a misconfiguration counts 0.6, an exposure 0.25).
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    weighted = {"critical": 0.0, "high": 0.0, "medium": 0.0, "low": 0.0}
    by_category = {"vulnerability": 0, "misconfiguration": 0, "exposure": 0, "info": 0}
    for mod_name, mod in results.items():
        if not isinstance(mod, dict):
            continue
        r = mod.get("risk", "low")
        for finding in mod.get("findings") or []:
            cat = _finding_category(mod_name, finding)
            by_category[cat] += 1
            if cat == "info" or r not in counts:
                continue
            counts[r] += 1
            weighted[r] += CATEGORY_SCORE_WEIGHT[cat]

    penalty = (
        25 * (1 - math.exp(-weighted["critical"] / 2))      # saturate ~6 criticals
        + 12 * (1 - math.exp(-weighted["high"] / 5))        # saturate ~12 highs
        + 4 * (1 - math.exp(-weighted["medium"] / 12))      # saturate ~35 mediums
    )
    score = round(max(0, min(100, base - penalty)))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    # Cap: the letter can never look better than the worst finding allows,
    # and the score follows the cap so number and letter stay coherent.
    if counts["critical"] > 0 and grade in ("A", "B", "C"):
        grade = "D"
        score = min(score, 59)
    elif counts["high"] > 0 and grade in ("A", "B"):
        grade = "C"
        score = min(score, 74)
    elif counts["medium"] > 0 and grade == "A":
        grade = "B"
        score = min(score, 89)
    # Overall risk: only non-info modules can raise it — a large but clean
    # inventory must not read as "high risk".
    scored_risks = [
        r for name, r in zip(module_names, module_risks)
        if MODULE_FINDING_CATEGORY.get(name, DEFAULT_FINDING_CATEGORY) != "info"
    ]
    overall_risk = _max_risk(*scored_risks) if scored_risks else "low"
    return {"score": score, "grade": grade, "overall_risk": overall_risk,
            "findings_by_severity": counts, "findings_by_category": by_category}


# ── Scanner orchestrator (sync — runs in a worker thread) ──────────────────────
# Modules whose results feed the asset inventory; after each of them finishes,
# the assets it produces are upserted immediately (incremental inventory).
ASSET_PRODUCING_MODULES = {
    "subdomains", "dns", "ports", "js_secrets", "tech",
    "admin", "exposed", "mobile_apps", "reverse_ip", "smart_fuzz",
}

# Lightweight discovery pass: builds the full asset inventory (subdomains, IPs,
# ports, endpoints/paths via fuzzing + JS mining, tech, apps, neighbors) without
# the risk-evaluation modules (ssl/tls/blacklist/breach/nuclei...).
DISCOVER_MODULES = {
    "whois", "dns", "subdomains", "reverse_ip",
    "tech", "robots", "js_secrets", "exposed", "admin", "api_exposure",
    "mobile_apps", "smart_fuzz",   # path fuzzing IS surface mapping
}

# Pure surface-mapping modules skipped when a scan runs with skip_discovery
# (vulnerability-only mode: evaluate the inventoried assets as-is).
SKIP_ON_VULN_ONLY = {"whois", "subdomains", "reverse_ip", "mobile_apps"}

# Host scan (kind="host", launched per-asset via POST /api/host-scan): only
# modules that evaluate a single host. Discovery-scope modules (subdomain enum,
# whois, email, mobile apps, leaks, wayback...) don't apply to one host, and
# the chained subdomain_eval step is skipped (host scans discover nothing new).
HOST_SCAN_MODULES = {
    "dns", "ssl", "tls", "headers", "cors", "cookies",
    "tech", "waf", "robots", "admin", "frontend_cve",
    "js_secrets", "secret_verification", "smart_fuzz", "blacklist",
    "exposed", "api_exposure", "ports", "reverse_ip", "nuclei",
}

# Every module the orchestrator can run, in execution order. Used by the
# settings API (enabled_modules map) and its validation.
SCAN_MODULE_NAMES = [
    "whois", "dns", "dnssec", "subdomains", "ssl", "tls", "headers", "cors",
    "cookies", "email", "tech", "mobile_apps", "waf", "robots", "admin",
    "frontend_cve", "js_secrets", "secret_verification", "smart_fuzz", "blacklist",
    "exposed", "breach", "cloud_storage", "api_exposure", "wayback", "ports",
    "reverse_ip", "nuclei", "subdomain_eval",
]

# Modules runnable standalone via a manual module scan (kind="module").
# subdomain_eval is chained to the subdomains module and cannot run alone.
MODULE_SCANNABLE = [n for n in SCAN_MODULE_NAMES if n != "subdomain_eval"]
MODULE_SCAN_MAX = 5

# ── App settings (admin-editable, persisted in app_settings) ──────────────────
SETTINGS_KEYS = ("enabled_modules", "agent_default_steps", "default_interval_hours",
                 "chain_eval_enabled", "chain_eval_max_targets",
                 "chain_eval_fuzz", "chain_eval_scope",
                 "agent_mode_default", "auto_discover_domains",
                 "smart_fuzz_enabled", "smart_fuzz_max_requests",
                 "tools_subfinder", "tools_httpx", "tools_katana",
                 "tools_naabu", "tools_trufflehog",
                 "discovery_enabled", "vuln_scan_enabled",
                 "default_discover_interval_hours", "skip_discovery_default")
DEFAULT_AGENT_STEPS = 15
DEFAULT_INTERVAL_HOURS = 24
DEFAULT_DISCOVER_INTERVAL_HOURS = 720  # 30 days
DEFAULT_CHAIN_EVAL_MAX = 10
DEFAULT_SMART_FUZZ_MAX_REQUESTS = 2000
SMART_FUZZ_MAX_REQUESTS_CAP = 10000


def _default_enabled_modules() -> dict[str, bool]:
    return {name: True for name in SCAN_MODULE_NAMES}


def _merge_settings(stored: dict[str, Any]) -> dict[str, Any]:
    """Stored rows over defaults; unknown/garbage values fall back to defaults."""
    enabled = _default_enabled_modules()
    saved = stored.get("enabled_modules")
    if isinstance(saved, dict):
        for name, flag in saved.items():
            if name in enabled:
                enabled[name] = bool(flag)
    steps = stored.get("agent_default_steps")
    interval = stored.get("default_interval_hours")
    chain_enabled = stored.get("chain_eval_enabled")
    chain_max = stored.get("chain_eval_max_targets")
    chain_fuzz = stored.get("chain_eval_fuzz")
    chain_scope = stored.get("chain_eval_scope")
    agent_mode_default = stored.get("agent_mode_default")
    auto_discover = stored.get("auto_discover_domains")
    fuzz_enabled = stored.get("smart_fuzz_enabled")
    fuzz_max = stored.get("smart_fuzz_max_requests")
    discovery_enabled = stored.get("discovery_enabled")
    vuln_scan_enabled = stored.get("vuln_scan_enabled")
    discover_interval = stored.get("default_discover_interval_hours")
    skip_discovery_default = stored.get("skip_discovery_default")
    tools = {
        name: stored.get(f"tools_{name}") if isinstance(stored.get(f"tools_{name}"), bool) else True
        for name in tools_runner.TOOLS
    }
    return {
        "enabled_modules": enabled,
        "agent_default_steps": steps if isinstance(steps, int) and steps >= 1 else DEFAULT_AGENT_STEPS,
        "default_interval_hours": interval if isinstance(interval, int) and interval >= 1 else DEFAULT_INTERVAL_HOURS,
        "chain_eval_enabled": chain_enabled if isinstance(chain_enabled, bool) else True,
        "chain_eval_max_targets": chain_max if isinstance(chain_max, int) and 1 <= chain_max <= 50 else DEFAULT_CHAIN_EVAL_MAX,
        "chain_eval_fuzz": chain_fuzz if isinstance(chain_fuzz, bool) else True,
        "chain_eval_scope": chain_scope if chain_scope in ("new", "all") else "new",
        "agent_mode_default": agent_mode_default if isinstance(agent_mode_default, bool) else False,
        "auto_discover_domains": auto_discover if isinstance(auto_discover, bool) else False,
        "smart_fuzz_enabled": fuzz_enabled if isinstance(fuzz_enabled, bool) else True,
        "smart_fuzz_max_requests": fuzz_max if isinstance(fuzz_max, int) and 1 <= fuzz_max <= SMART_FUZZ_MAX_REQUESTS_CAP else DEFAULT_SMART_FUZZ_MAX_REQUESTS,
        "discovery_enabled": discovery_enabled if isinstance(discovery_enabled, bool) else True,
        "vuln_scan_enabled": vuln_scan_enabled if isinstance(vuln_scan_enabled, bool) else True,
        "default_discover_interval_hours": discover_interval if isinstance(discover_interval, int) and discover_interval >= 1 else DEFAULT_DISCOVER_INTERVAL_HOURS,
        "skip_discovery_default": skip_discovery_default if isinstance(skip_discovery_default, bool) else False,
        **{f"tools_{name}": flag for name, flag in tools.items()},
    }


async def _load_settings() -> dict[str, Any]:
    rows = await AppSetting.all()
    return _merge_settings({row.key: row.value for row in rows})


def _settings_payload(settings: dict[str, Any]) -> dict[str, Any]:
    ai_configured = bool(os.getenv("AI_API_KEY", "").strip())
    proxy_on = proxy_pool.enabled()
    return settings | {
        "ai": {
            "configured": ai_configured,
            "model": os.getenv("AI_MODEL", "gpt-4o-mini") if ai_configured else None,
        },
        "proxy": {
            "enabled": proxy_on,
            "pool_size": len(proxy_pool._configured_proxies()) if proxy_on else 0,
        },
        "notify": {"configured": bool(os.getenv("NOTIFY_WEBHOOK_URL", "").strip())},
    }


class _ScanStopped(Exception):
    """Raised inside _run_scan when the user requested a stop."""


def _chained_eval_step(scan_id: str, domain: str, subdomains_result: dict,
                       settings: dict | None, enabled_modules: dict) -> dict:
    """Chained evaluation of subdomains (full scans only).

    Target selection: with chain_eval_scope="new" (default), scans after the
    first evaluate only subdomains absent from the previous completed scan
    (SCANS[scan_id]["prev_subdomains"], loaded by _run_and_persist_scan). On
    the FIRST scan of a domain everything would be "new" (hundreds of targets),
    so instead we evaluate only the hosts already proven active by DNS
    resolution, capped at chain_eval_max_targets. With chain_eval_scope="all"
    every DNS-active subdomain is re-evaluated each scan (same cap). Either
    way the module re-probes each target for HTTP aliveness before evaluating,
    and chain_eval_fuzz gates the light fuzz step (exposed files + admin
    panels) per alive host.
    """
    settings = settings or {}
    if not settings.get("chain_eval_enabled", True):
        return subdomain_eval.skipped("chain_eval_enabled is off in settings")
    if enabled_modules.get("subdomain_eval") is False:
        return subdomain_eval.skipped("module disabled in settings")
    cap = settings.get("chain_eval_max_targets") or DEFAULT_CHAIN_EVAL_MAX
    entries = (subdomains_result or {}).get("subdomains") or []
    current = [s["subdomain"] for s in entries if isinstance(s, dict) and s.get("subdomain")]
    if settings.get("chain_eval_scope", "new") == "all":
        # Re-evaluate every DNS-active subdomain each scan, capped.
        targets = [s["subdomain"] for s in entries
                   if isinstance(s, dict) and s.get("status") == "active" and s.get("subdomain")][:cap]
    else:
        prev = SCANS[scan_id].get("prev_subdomains") or []
        if prev:
            targets = [s for s in current if s not in set(prev)][:cap]
        else:
            # First scan: cap over the alive (DNS-active) subdomains only.
            targets = [s["subdomain"] for s in entries
                       if isinstance(s, dict) and s.get("status") == "active" and s.get("subdomain")][:cap]
    if not targets:
        return subdomain_eval.skipped("no new subdomains")
    SCANS[scan_id]["current_module"] = "subdomain_eval"
    SCANS[scan_id]["progress"] = 19
    fuzz = settings.get("chain_eval_fuzz", True)
    logger.info(f"[{scan_id}] Running module: subdomain_eval ({len(targets)} target(s), fuzz={fuzz})")
    start = time.time()
    try:
        result = subdomain_eval.run(domain, targets, fuzz=fuzz)
        logger.info(f"[{scan_id}] subdomain_eval completed in {round(time.time() - start, 2)}s")
        return result
    except Exception as e:
        logger.error(f"[{scan_id}] Module subdomain_eval crashed: {e}")
        return {"status": "error", "error": str(e), "evaluated": [], "evaluated_count": 0,
                "alive_count": 0, "secret_verification": None, "risk": "low", "findings": []}


def _run_scan(scan_id: str, domain: str, on_module_done=None, settings: dict | None = None) -> dict:
    SCANS[scan_id]["status"] = "running"
    kind = SCANS[scan_id].get("kind", "full")
    enabled_modules = (settings or {}).get("enabled_modules") or {}
    # Snapshot tools_* flags for this scan (context-local — safe with
    # SCAN_WORKERS > 1); modules consult them via tools_runner.tool_enabled().
    tools_runner.set_tool_flags(settings)
    results: dict[str, Any] = {}
    # Handoff channel for full candidate key values extracted by js_secrets.
    # js_secrets.pop("_raw") fills it; secret_verification reads it via closure.
    handoff: dict[str, Any] = {}

    def _secret_verification_run(d: str) -> dict:
        return secret_verification.run(d, handoff.get("raw"))

    def _mobile_apps_run(d: str) -> dict:
        return mobile_apps.run(d, app_developers=SCANS[scan_id].get("app_developers"))

    def _smart_fuzz_run(d: str) -> dict:
        # Manual module scans are explicit intent: the settings toggle does
        # not apply when smart_fuzz was explicitly requested.
        if kind != "module" and not (settings or {}).get("smart_fuzz_enabled", True):
            return {"status": "skipped", "reason": "smart_fuzz_enabled is off in settings",
                    "wordlist_used": [], "requests_made": 0, "paths_found": [],
                    "waf_blocked": False, "risk": "low", "findings": []}
        tech = results.get("tech") or {}
        tech_hints = tech.get("technologies") or []
        endpoints = (results.get("js_secrets") or {}).get("endpoints") or []
        known = [e.get("path") or e.get("endpoint") for e in endpoints if isinstance(e, dict)]
        known = [p for p in known if p]
        max_req = (settings or {}).get("smart_fuzz_max_requests") or DEFAULT_SMART_FUZZ_MAX_REQUESTS
        return smart_fuzz.run(d, wordlist="auto", max_requests=max_req,
                              tech_hints=tech_hints, known_endpoints=known[:50])

    modules = [
        ("whois",      whois_lookup.run,    4),
        ("dns",        dns_enum.run,         8),
        ("dnssec",     dnssec_check.run,    11),
        ("subdomains", subdomain_enum.run,  17),   # passive DNS / crt.sh before HTTP probing
        ("ssl",        ssl_check.run,       21),
        ("tls",        tls_audit.run,       24),
        ("headers",    headers_check.run,   28),
        ("cors",       cors_check.run,      32),
        ("cookies",    cookie_security.run, 36),
        ("email",      email_security.run,  40),
        ("tech",       tech_fingerprint.run,44),
        ("mobile_apps", _mobile_apps_run,   46),
        ("waf",        waf_detect.run,      48),
        ("robots",     robots_sitemap.run,  52),
        ("admin",        admin_discovery.run,  58),
        ("frontend_cve", frontend_cve.run,     62),
        ("js_secrets",   js_secrets.run,       66),
        ("secret_verification", _secret_verification_run, 67),
        ("smart_fuzz", _smart_fuzz_run,   69),   # active probing: also runs in discovery passes (surface mapping)
        ("blacklist",  blacklist_check.run, 70),
        ("exposed",    exposed_files.run,   76),
        ("breach",        breach_check.run,         82),
        ("cloud_storage", cloud_metadata.run,       86),
        ("api_exposure",  api_exposure.run,           89),
        ("wayback",       wayback_secrets.run,        92),
        ("ports",         port_scan.run,              95),
        ("reverse_ip",    reverse_ip.run,             96),
        ("nuclei",        nuclei_integration.run,     98),
    ]

    module_allowlist = SCANS[scan_id].get("modules_allowlist") or []
    # Planned module list — what this scan will actually run, so the progress
    # UI can show exactly these (no ghost rows for modules that don't apply).
    planned: list[str] = []
    for name, _func, _progress in modules:
        if kind == "discover" and name not in DISCOVER_MODULES:
            continue
        if kind == "host" and name not in HOST_SCAN_MODULES:
            continue
        if kind == "module" and name not in module_allowlist:
            continue
        if SCANS[scan_id].get("skip_discovery") and name in SKIP_ON_VULN_ONLY:
            continue
        if kind != "module" and enabled_modules.get(name) is False:
            continue
        planned.append(name)
        if name == "subdomains" and kind == "full":
            planned.append("subdomain_eval")
    if SCANS[scan_id].get("agent_mode"):
        planned.append("agent")
    SCANS[scan_id]["planned_modules"] = planned
    for name, func, progress in modules:
        if SCANS[scan_id].get("stop_requested"):
            logger.info(f"[{scan_id}] Stop requested — halting before module {name}")
            raise _ScanStopped()
        if kind == "discover" and name not in DISCOVER_MODULES:
            continue
        # Host scans evaluate a single host: skip discovery-scope modules.
        if kind == "host" and name not in HOST_SCAN_MODULES:
            continue
        # Module scans run only the explicitly requested modules.
        if kind == "module" and name not in module_allowlist:
            continue
        # Vulnerability-only scan: skip pure surface-mapping modules
        if SCANS[scan_id].get("skip_discovery") and name in SKIP_ON_VULN_ONLY:
            results[name] = {"status": "skipped", "reason": "skip_discovery", "findings": [], "risk": "low"}
            continue
        # The enabled_modules settings filter does NOT apply to module scans:
        # the user's explicit request is the intent (a module that cannot run
        # at all, e.g. missing nuclei binary, still degrades to "skipped"
        # inside the module itself).
        if kind != "module" and enabled_modules.get(name) is False:
            logger.info(f"[{scan_id}] Module {name} disabled in settings — skipped")
            results[name] = {"status": "skipped", "findings": [], "risk": "low"}
            continue
        SCANS[scan_id]["current_module"] = name
        SCANS[scan_id]["progress"] = progress
        try:
            logger.info(f"[{scan_id}] Running module: {name}")
            start = time.time()
            results[name] = func(domain)
            if name == "js_secrets":
                handoff["raw"] = results[name].pop("_raw", None)
            elapsed = round(time.time() - start, 2)
            logger.info(f"[{scan_id}] {name} completed in {elapsed}s")
        except Exception as e:
            logger.error(f"[{scan_id}] Module {name} crashed: {e}")
            results[name] = {"status": "error", "error": str(e)}
        if on_module_done is not None and name in ASSET_PRODUCING_MODULES:
            try:
                on_module_done(name, dict(results))
            except Exception:
                logger.exception(f"[{scan_id}] Incremental asset upsert failed after {name}")
        # Chained evaluation: right after enumeration, give the newly discovered
        # subdomains a light eval (full scans only; see _chained_eval_step).
        if name == "subdomains" and kind == "full":
            results["subdomain_eval"] = _chained_eval_step(
                scan_id, domain, results["subdomains"], settings, enabled_modules)

    # Aggregate summary — each step degrades independently instead of killing the scan
    all_findings = []
    for mod_name, mod_result in results.items():
        if not isinstance(mod_result, dict):
            continue
        for finding in mod_result.get("findings") or []:
            all_findings.append({
                "module": mod_name,
                "finding": finding,
                "risk": mod_result.get("risk", "low"),
                "category": _finding_category(mod_name, finding),
            })

    # Discovery passes build inventory only — no rating, no grade: they never
    # ran the evaluation modules, so a score would be misleading.
    if kind == "discover":
        scorecard = {"score": None, "grade": None, "overall_risk": "low",
                     "note": "discovery pass — inventory only, no evaluation"}
    elif kind == "module":
        # Module scans are partial by definition: no score/grade (they would
        # not be comparable to a full evaluation), but the worst module risk
        # is still surfaced. Excluded from domain ratings by the kind filters
        # on every latest-scan query.
        risks = [m.get("risk", "low") for m in results.values() if isinstance(m, dict)]
        scorecard = {"score": None, "grade": None,
                     "overall_risk": _max_risk(*risks) if risks else "low",
                     "note": "module scan — partial evaluation, no domain rating"}
    else:
        try:
            scorecard = _overall_score(results)
        except Exception as e:
            logger.exception(f"[{scan_id}] Scorecard computation failed — degraded result")
            scorecard = {"score": None, "grade": None, "overall_risk": "low",
                         "error": f"scorecard failed: {e}"}

    result = {
        "domain": domain,
        "kind": kind,
        "scanned_at": SCANS[scan_id]["started_at"],
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "scorecard": scorecard,
        "findings": sorted(all_findings, key=lambda f: RISK_ORDER.get(f["risk"], 0), reverse=True),
        "modules": results,
    }

    # Optional AI layer — after the scorecard, never part of the score,
    # and never allowed to break the scan. Discovery scans skip it; host
    # scans only get it in agent_mode.
    if kind == "full" or (kind == "host" and SCANS[scan_id].get("agent_mode")):
        try:
            result["ai_summary"] = ai_summary.run(result)
        except Exception as e:
            logger.error(f"[{scan_id}] ai_summary crashed: {e}")
            result["ai_summary"] = {"status": "error", "error": str(e)}

    # Optional agent phase — LLM investigates the deterministic results.
    # Status stays "running" with current_module="agent" until it ends.
    # Agent findings are appended to result["findings"] with module="agent"
    # and may raise scorecard.overall_risk, but NEVER the numeric score/grade
    # (the scorecard remains purely deterministic).
    if SCANS[scan_id].get("agent_mode"):
        SCANS[scan_id].update({"current_module": "agent", "progress": 99, "agent_steps": []})
        try:
            agent_result = agent_scan.run(
                domain,
                result,
                max_steps=SCANS[scan_id].get("max_steps")
                    or (settings or {}).get("agent_default_steps")
                    or agent_scan.DEFAULT_MAX_STEPS,
                extra_allowed=set(SCANS[scan_id].get("extra_allowed") or []),
                on_step=lambda step: SCANS[scan_id]["agent_steps"].append(step),
            )
        except Exception as e:
            logger.exception(f"[{scan_id}] agent_scan crashed")
            agent_result = {"status": "error", "steps": [], "summary": "",
                            "findings": [], "assets_discovered": 0, "error": str(e)}
        result["agent_steps"] = agent_result["steps"]
        result["agent_summary"] = agent_result["summary"]
        result["agent_status"] = agent_result["status"]
        result["assets_discovered"] = agent_result["assets_discovered"]
        if agent_result.get("error"):
            result["agent_error"] = agent_result["error"]
        if agent_result["findings"]:
            for f in agent_result["findings"]:
                # Agent findings are appended after the scorecard; tag them and
                # keep findings_by_category coherent (score/grade untouched —
                # the scorecard remains purely deterministic).
                f.setdefault("category", _finding_category("agent", f.get("finding")))
            result["findings"] = sorted(
                result["findings"] + agent_result["findings"],
                key=lambda f: RISK_ORDER.get(f["risk"], 0), reverse=True,
            )
            by_cat = result["scorecard"].setdefault("findings_by_category",
                {"vulnerability": 0, "misconfiguration": 0, "exposure": 0, "info": 0})
            for f in agent_result["findings"]:
                by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
            result["scorecard"]["overall_risk"] = _max_risk(
                result["scorecard"]["overall_risk"],
                *(f["risk"] for f in agent_result["findings"]),
            )
        # The agent phase runs after the deterministic pipeline, so the scan's
        # completed_at must reflect its real end.
        result["completed_at"] = datetime.now(timezone.utc).isoformat()

    SCANS[scan_id].update(
        {
            "status": "completed",
            "progress": 100,
            "current_module": None,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
    )
    return result


# ── Persistence & diffing (async — runs in the queue worker context) ───────────
async def _run_and_persist_scan(scan_id: str, domain: str, domain_id: int | None) -> None:
    # The Scan row already exists (created as "queued" at enqueue time).
    await Scan.filter(id=scan_id).update(status="running", current_module=None)
    # Resolve the domain row up-front so the scanner thread can push
    # incremental asset upserts back onto this loop after each module.
    dom = await Domain.get_or_none(id=domain_id) if domain_id is not None else None
    if dom is None:
        dom = await _get_or_create_domain(None, domain)
    # Settings and per-domain config are read here (async) and handed to the
    # sync orchestrator thread, which has no DB access.
    settings = await _load_settings()
    if scan_id in SCANS:
        SCANS[scan_id]["app_developers"] = dom.app_developers or []
        # Baseline for chained evaluation: subdomains seen by the last completed
        # scan of this domain. None completed yet → [] (first-scan behavior:
        # subdomain_eval caps over DNS-active hosts only, see _chained_eval_step).
        # Host scans never qualify as the baseline (they enumerate nothing).
        prev = await Scan.filter(domain_id=dom.id, status="completed",
                                 kind__in=["full", "discover"]) \
            .order_by("-completed_at", "-started_at").first()
        SCANS[scan_id]["prev_subdomains"] = (
            sorted(_extract_subdomains(prev.result)) if prev and prev.result else []
        )
    loop = asyncio.get_running_loop()

    def on_module_done(module_name: str, results_so_far: dict) -> None:
        coro = _upsert_assets_incremental(dom, results_so_far, scan_id)
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            future.result(timeout=60)
        except Exception:
            logger.exception(f"[{scan_id}] Incremental asset upsert failed after {module_name}")

    # Skip scans that were stopped while still in the queue
    if SCANS.get(scan_id, {}).get("stop_requested"):
        await Scan.filter(id=scan_id).update(status="interrupted", current_module=None)
        SCANS.pop(scan_id, None)
        logger.info(f"[{scan_id}] Skipped (stopped while queued)")
        return

    try:
        result = await asyncio.to_thread(_run_scan, scan_id, domain, on_module_done, settings)
    except _ScanStopped:
        logger.info(f"[{scan_id}] Scan stopped by user")
        await Scan.filter(id=scan_id).update(
            status="interrupted",
            current_module=None,
            completed_at=datetime.now(timezone.utc),
        )
        SCANS.pop(scan_id, None)
        return
    except Exception as e:
        logger.exception(f"[{scan_id}] Scan crashed")
        if scan_id in SCANS:
            SCANS[scan_id]["status"] = "failed"
        try:
            await _persist_failed_scan(scan_id, domain, domain_id, str(e))
        except Exception:
            logger.exception(f"[{scan_id}] Failed to persist failed scan")
        SCANS.pop(scan_id, None)
        return
    try:
        await _persist_completed_scan(scan_id, domain, domain_id, result)
        SCANS.pop(scan_id, None)  # completed scans live in the DB from now on
    except Exception:
        # Keep the completed scan in memory so it stays reachable until restart
        logger.exception(f"[{scan_id}] Persistence failed — keeping result in memory only")


async def _get_or_create_company(name: str) -> Company:
    company = await Company.get_or_none(name=name)
    if company is None:
        company = await Company.create(name=name)
    return company


async def _get_or_create_domain(company_id: int | None, domain: str) -> Domain:
    existing = await Domain.get_or_none(company_id=company_id, domain=domain)
    if existing is not None:
        return existing
    # A quick scan may have parked this domain in an orphan row (no company).
    # Adopt it instead of creating a duplicate with split history.
    orphan = await Domain.get_or_none(company_id=None, domain=domain)
    if orphan is not None and company_id is not None:
        orphan.company_id = company_id
        await orphan.save()
        logger.info(f"Adopted orphan domain row {orphan.id} for {domain} into company {company_id}")
        return orphan
    if company_id is None:
        # Quick scan of a domain that already belongs to a company: reuse that
        # row so scans and assets share one inventory.
        linked = await Domain.filter(domain=domain).first()
        if linked is not None:
            return linked
    return await Domain.create(company_id=company_id, domain=domain)


def _extract_subdomains(result: dict) -> set[str]:
    subs = (result.get("modules", {}).get("subdomains") or {}).get("subdomains") or []
    return {s.get("subdomain") for s in subs if isinstance(s, dict) and s.get("subdomain")}


def _extract_endpoints(result: dict) -> dict[str, str]:
    modules = result.get("modules", {})
    eps = (modules.get("js_secrets") or {}).get("endpoints") or []
    out: dict[str, str] = {}
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        path = ep.get("path") or ep.get("endpoint")
        if path:
            out.setdefault(path, ep.get("source") or "")
    # smart_fuzz hits also enter the endpoint inventory (source "smart_fuzz")
    for hit in (modules.get("smart_fuzz") or {}).get("paths_found") or []:
        if isinstance(hit, dict) and hit.get("path"):
            out.setdefault(hit["path"], "smart_fuzz")
    return out


def _extract_findings(result: dict) -> set[str]:
    return {
        f.get("finding")
        for f in result.get("findings", [])
        if isinstance(f, dict) and f.get("finding")
    }


# ── Persistent findings (remediation tracking) ────────────────────────────────
def _finding_text(finding) -> str:
    """Stable string form of a raw finding (usually a string, sometimes a dict)."""
    if isinstance(finding, str):
        return finding
    try:
        return json.dumps(finding, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        return str(finding)


def _finding_fingerprint(domain: str, module: str, text: str) -> str:
    """Stable identity of a finding across scans: sha1 of
    domain|module|normalized-text. Normalization collapses whitespace so
    cosmetic formatting differences don't spawn duplicate rows."""
    normalized = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha1(f"{domain}|{module}|{normalized}".encode("utf-8")).hexdigest()


async def _upsert_findings(dom: Domain, result: dict, scan_id: str) -> None:
    """Upsert the scan's aggregated findings as persistent Finding rows and
    auto-resolve whatever disappeared. Full scans upsert AND sweep; host and
    module scans upsert only (they cover a single host / a module subset, so
    sweeping on them would wrongly auto-fix findings they never checked);
    discovery passes don't run the evaluation modules and are skipped entirely."""
    kind = result.get("kind", "full")
    if kind not in ("full", "host", "module"):
        return
    now = datetime.now(timezone.utc)
    seen_fps: set[str] = set()
    for f in result.get("findings") or []:
        if not isinstance(f, dict):
            continue
        text = _finding_text(f.get("finding"))
        if not text:
            continue
        module = f.get("module") or "unknown"
        fp = _finding_fingerprint(dom.domain, module, text)
        seen_fps.add(fp)
        risk = f.get("risk") if f.get("risk") in RISK_ORDER else "low"
        category = f.get("category") or _finding_category(module, f.get("finding"))
        frameworks = compliance.frameworks_for(module, text)
        existing = await Finding.get_or_none(domain_id=dom.id, fingerprint=fp)
        if existing is None:
            await Finding.create(
                domain_id=dom.id, fingerprint=fp, module=module, text=text,
                risk=risk, category=category, frameworks=frameworks,
                status="open",
                first_seen_scan_id=scan_id, last_seen_scan_id=scan_id,
                first_seen_at=now, last_seen_at=now,
            )
            continue
        existing.last_seen_scan_id = scan_id
        existing.last_seen_at = now
        existing.risk = risk
        existing.category = category
        existing.frameworks = frameworks
        if existing.status == "fixed":
            # A finding that was resolved (manually or automatically) is back
            # in the scan output — reopen it.
            existing.status = "open"
            existing.fixed_at = None
            logger.info(f"[{scan_id}] Finding #{existing.id} reopened (reappeared in scan)")
        await existing.save()
    # Sweep: open findings of this domain NOT seen in this scan are gone from
    # the attack surface — auto-resolve them. Accepted findings keep their
    # status (accepted is an operator decision, not a presence signal).
    # Host/module scans never sweep: they only see part of the attack surface.
    if kind != "full":
        return
    stale = await Finding.filter(domain_id=dom.id, status="open") \
        .exclude(last_seen_scan_id=scan_id)
    if stale:
        for rec in stale:
            rec.status = "fixed"
            rec.fixed_at = now
            await rec.save()
        logger.info(
            f"[{scan_id}] Auto-fixed {len(stale)} finding(s) no longer detected "
            f"for {dom.domain}: ids {[r.id for r in stale]}"
        )


def _compute_changes(prev_result: dict | None, cur_result: dict, prev_scan_id: str | None) -> dict:
    if not prev_result:
        return {
            "new_subdomains": [],
            "new_endpoints": [],
            "new_findings": [],
            "score_delta": None,
            "previous_grade": None,
            "previous_scan_id": None,
        }
    prev_subs, cur_subs = _extract_subdomains(prev_result), _extract_subdomains(cur_result)
    prev_eps, cur_eps = _extract_endpoints(prev_result), _extract_endpoints(cur_result)
    prev_findings, cur_findings = _extract_findings(prev_result), _extract_findings(cur_result)
    prev_score = (prev_result.get("scorecard") or {}).get("score")
    cur_score = (cur_result.get("scorecard") or {}).get("score")
    return {
        "new_subdomains": sorted(cur_subs - prev_subs),
        "new_endpoints": [
            {"path": p, "source": cur_eps[p]} for p in sorted(set(cur_eps) - set(prev_eps))
        ],
        "new_findings": sorted(cur_findings - prev_findings),
        "score_delta": (cur_score - prev_score) if prev_score is not None and cur_score is not None else None,
        "previous_grade": (prev_result.get("scorecard") or {}).get("grade"),
        "previous_scan_id": prev_scan_id,
    }


async def _upsert_subdomains(domain_id: int, result: dict, scan_id: str) -> None:
    names = sorted(_extract_subdomains(result))
    if not names:
        return
    existing = await Subdomain.filter(domain_id=domain_id, subdomain__in=names)
    seen = {e.subdomain: e for e in existing}
    for name in names:
        if name in seen:
            rec = seen[name]
            rec.last_seen_scan_id = scan_id
            await rec.save()
        else:
            await Subdomain.create(
                domain_id=domain_id, subdomain=name,
                first_seen_scan_id=scan_id, last_seen_scan_id=scan_id,
            )


async def _upsert_endpoints(domain_id: int, result: dict, scan_id: str) -> None:
    endpoints = _extract_endpoints(result)
    if not endpoints:
        return
    existing = await Endpoint.filter(domain_id=domain_id, path__in=list(endpoints))
    seen = {e.path: e for e in existing}
    for path, source in endpoints.items():
        if path in seen:
            rec = seen[path]
            rec.last_seen_scan_id = scan_id
            await rec.save()
        else:
            await Endpoint.create(
                domain_id=domain_id, path=path, source=source,
                first_seen_scan_id=scan_id, last_seen_scan_id=scan_id,
            )


# ── Asset inventory (upsert on scan completion) ───────────────────────────────
# Coarse category map for tech_fingerprint's technology names; the module
# itself does not categorize. Unknown names fall back to "other".
TECH_CATEGORIES = {
    "Apache": "server", "Nginx": "server", "IIS": "server",
    "LiteSpeed": "server", "OpenResty": "server",
    "PHP": "language", "ASP.NET": "framework", "Express.js": "framework",
    "Ruby on Rails": "framework", "Next.js": "framework",
    "React": "framework", "Vue.js": "framework", "Angular": "framework",
    "Nuxt.js": "framework",
    "Cloudflare": "cdn", "Fastly": "cdn", "Varnish": "cdn", "AWS CloudFront": "cdn",
    "reCAPTCHA": "security", "hCaptcha": "security",
    "WordPress": "cms", "Drupal": "cms", "Joomla": "cms", "Ghost": "cms",
    "Shopify": "cms", "Magento": "cms", "Wix": "cms", "Squarespace": "cms",
    "Google Analytics": "analytics", "Google Tag Manager": "analytics",
    "Facebook Pixel": "analytics",
    "jQuery": "library", "Bootstrap": "library", "Font Awesome": "library",
}


def _extract_asset_candidates(dom: Domain, result: dict) -> dict[tuple[str, str], dict]:
    """Pull unified asset candidates {(type, value): metadata} out of a
    completed scan result. Fed from: subdomains, dns, ports, js_secrets,
    tech, admin, exposed, mobile_apps and reverse_ip modules."""
    modules = result.get("modules", {})
    subs_mod = modules.get("subdomains") or {}
    dns_mod = modules.get("dns") or {}
    ports_mod = modules.get("ports") or {}
    tech_mod = modules.get("tech") or {}
    admin_mod = modules.get("admin") or {}
    exposed_mod = modules.get("exposed") or {}
    apps_mod = modules.get("mobile_apps") or {}
    reverse_mod = modules.get("reverse_ip") or {}

    wanted: dict[tuple[str, str], dict] = {}

    # ip -> hostnames that resolve to it (apex A records + subdomain IPs).
    # For host scans result["domain"] is the host itself (dom.domain stays the
    # parent apex), so its A records attribute to the right hostname.
    target = result.get("domain") or dom.domain
    ip_hosts: dict[str, set[str]] = {}
    sub_entries = [s for s in (subs_mod.get("subdomains") or []) if isinstance(s, dict) and s.get("subdomain")]
    for entry in sub_entries:
        for ip in entry.get("ips") or []:
            ip_hosts.setdefault(ip, set()).add(entry["subdomain"])
    for ip in (dns_mod.get("records") or {}).get("A") or []:
        ip_hosts.setdefault(ip, set()).add(target)

    # port_scan only probes the apex IP
    apex_ip = ports_mod.get("ip")
    open_ports = [p for p in (ports_mod.get("open_ports") or []) if isinstance(p, dict) and p.get("port")]
    ports_by_ip: dict[str, list[dict]] = {}
    if apex_ip and open_ports:
        ports_by_ip[apex_ip] = [{"port": p["port"], "service": p.get("service")} for p in open_ports]
        for p in ports_by_ip[apex_ip]:
            wanted[("port", f"{apex_ip}:{p['port']}")] = {"service": p.get("service")}

    for entry in sub_entries:
        wanted[("subdomain", entry["subdomain"])] = {
            "ips": sorted(entry.get("ips") or []),  # sorted: stable metadata, no order-flip history noise
            "http_status": None,  # subdomain_enum does not probe HTTP
            "status": entry.get("status"),
            "sensitive": bool(entry.get("sensitive")),
            "sources": sorted(entry.get("sources") or []),
        }

    # Host scans refresh the scanned host's own subdomain asset in place
    # (fresh IPs from its DNS records; enum/merge blocks only run on full scans).
    if result.get("kind") == "host" and target != dom.domain:
        key = ("subdomain", target)
        meta = wanted.get(key)
        host_ips = sorted((dns_mod.get("records") or {}).get("A") or [])
        if meta is None:
            wanted[key] = {
                "ips": host_ips,
                "http_status": None,
                "status": "active" if host_ips else None,
                "sensitive": False,
                "sources": ["host_scan"],
            }
        else:
            ips = set(meta.get("ips") or []) | set(host_ips)
            meta["ips"] = sorted(ips)
            sources = set(meta.get("sources") or [])
            sources.add("host_scan")
            meta["sources"] = sorted(sources)

    for ip, hosts in ip_hosts.items():
        wanted[("ip", ip)] = {
            "domains": sorted(hosts),
            "open_ports": ports_by_ip.get(ip, []),
            # port_scan only probes the apex IP: other IPs' open_ports would
            # be wiped to [] on every refresh, so flag which IP was scanned
            # and let _upsert_assets preserve the rest.
            "ports_scanned": bool(apex_ip and ip == apex_ip),
        }

    for path, source in _extract_endpoints(result).items():
        wanted[("endpoint", path)] = {"source": source}

    for tech in tech_mod.get("technologies") or []:
        if isinstance(tech, str) and tech:
            wanted[("technology", tech)] = {"category": TECH_CATEGORIES.get(tech, "other")}

    for panel in admin_mod.get("found") or []:
        if not isinstance(panel, dict):
            continue
        url = panel.get("url") or panel.get("path")
        if url:
            wanted[("admin_panel", url)] = {
                "http_status": panel.get("status"),
                "severity": panel.get("severity"),
            }

    for exposed in exposed_mod.get("exposed") or []:
        if not isinstance(exposed, dict) or not exposed.get("path"):
            continue
        wanted[("exposed_file", exposed["path"])] = {
            "risk": exposed.get("severity") or "low",
            "url": exposed.get("url"),
            "description": exposed.get("description"),
        }

    for app_entry in (apps_mod.get("apps") or []) + (apps_mod.get("suspicious") or []):
        if not isinstance(app_entry, dict) or not app_entry.get("name"):
            continue
        wanted[("app", app_entry["name"])] = {
            "store": app_entry.get("store"),
            "os": app_entry.get("os"),
            "version": app_entry.get("version"),
            "developer": app_entry.get("developer"),
            "url": app_entry.get("url"),
            "updated": app_entry.get("updated"),
            "llm_verdict": app_entry.get("llm_verdict"),
            "official_developer": bool(app_entry.get("official_developer")),
            "suspicious": app_entry in (apps_mod.get("suspicious") or []),
        }

    for neighbor in reverse_mod.get("neighbors") or []:
        if not isinstance(neighbor, dict) or not neighbor.get("domain"):
            continue
        wanted[("neighbor", neighbor["domain"])] = {
            "ip": neighbor.get("ip"),
            "neighbor_of": neighbor.get("neighbor_of"),
        }

    # Reverse-IP attributed hosts that are subdomains of the apex join the
    # subdomain inventory (merge IPs/sources if the enum already saw them)
    for attr in reverse_mod.get("attributed") or []:
        if not isinstance(attr, dict) or not attr.get("domain"):
            continue
        if attr.get("kind") != "subdomain":
            continue
        host = attr["domain"]
        key = ("subdomain", host)
        meta = wanted.get(key)
        if meta is None:
            wanted[key] = {
                "ips": sorted([attr["ip"]] if attr.get("ip") else []),
                "http_status": None,
                "status": None,
                "sensitive": False,
                "sources": ["reverse_ip"],
            }
        else:
            ips = set(meta.get("ips") or [])
            if attr.get("ip"):
                ips.add(attr["ip"])
            meta["ips"] = sorted(ips)
            sources = set(meta.get("sources") or [])
            sources.add("reverse_ip")
            meta["sources"] = sorted(sources)

    return {key: meta for key, meta in wanted.items() if key[1]}


async def _upsert_assets(dom: Domain, result: dict, scan_id: str) -> None:
    candidates = _extract_asset_candidates(dom, result)
    if not candidates:
        return
    existing = await Asset.filter(domain_id=dom.id)
    seen = {(a.type, a.value): a for a in existing}
    created = updated = 0
    for (atype, value), meta in candidates.items():
        key = (atype, value[:1024])
        rec = seen.get(key)
        if rec is not None:
            if rec.type == "ip" and not meta.get("ports_scanned"):
                old_ports = (rec.metadata or {}).get("open_ports")
                if old_ports:
                    meta = meta | {"open_ports": old_ports}
            if (rec.metadata or {}) != meta:
                # Record only meaningful metadata changes; ports_scanned is
                # internal bookkeeping that flips within a single scan.
                # Incremental upserts may chain several rows per scan — the
                # diff endpoint collapses them to earliest-old -> latest-new.
                changed_fields = {
                    f for f in set(rec.metadata or {}) | set(meta)
                    if (rec.metadata or {}).get(f) != meta.get(f)
                } - {"ports_scanned"}
                if changed_fields:
                    await AssetHistory.create(
                        asset=rec, scan_id=scan_id,
                        old_metadata=rec.metadata, new_metadata=meta,
                    )
            rec.last_seen_scan_id = scan_id
            rec.metadata = meta
            await rec.save()
            updated += 1
        else:
            await Asset.create(
                domain_id=dom.id, type=key[0], value=key[1], metadata=meta,
                first_seen_scan_id=scan_id, last_seen_scan_id=scan_id,
            )
            created += 1
    logger.info(f"[{scan_id}] Assets upserted for {dom.domain}: {created} new, {updated} refreshed")


async def _upsert_assets_incremental(dom: Domain, results_so_far: dict, scan_id: str) -> None:
    """Incremental inventory: upsert assets right after each asset-producing
    module so the inventory is live while the scan is still running."""
    partial_result = {"domain": dom.domain, "modules": results_so_far}
    await _upsert_assets(dom, partial_result, scan_id)


async def _persist_completed_scan(scan_id: str, domain: str, domain_id: int | None, result: dict) -> None:
    dom = await Domain.get_or_none(id=domain_id) if domain_id is not None else None
    if dom is None:
        dom = await _get_or_create_domain(None, domain)

    # Diff baseline: host scans diff against the previous HOST scan of the same
    # target, module scans against the previous MODULE scan of the same target;
    # full/discover scans against the previous full/discover scan — either way
    # a host/module scan never becomes the domain's "latest scan".
    kind = result.get("kind", "full")
    if kind in ("host", "module"):
        prev = await Scan.filter(domain_id=dom.id, status="completed",
                                 kind=kind, scan_target=domain) \
            .order_by("-completed_at", "-started_at").first()
    else:
        prev = await Scan.filter(domain_id=dom.id, status="completed",
                                 kind__in=["full", "discover"]) \
            .order_by("-completed_at", "-started_at").first()
    result["changes"] = _compute_changes(prev.result if prev else None, result, prev.id if prev else None)

    await _upsert_subdomains(dom.id, result, scan_id)
    await _upsert_endpoints(dom.id, result, scan_id)
    await _upsert_assets(dom, result, scan_id)
    # Persistent findings (remediation tracking) — best-effort, must never
    # break scan persistence.
    try:
        await _upsert_findings(dom, result, scan_id)
    except Exception:
        logger.exception(f"[{scan_id}] Findings upsert failed")

    values = {
        "domain_id": dom.id,
        "status": "completed",
        "progress": 100,
        "current_module": None,
        "started_at": datetime.fromisoformat(result["scanned_at"]),
        "completed_at": datetime.fromisoformat(result["completed_at"]),
        "scorecard": result["scorecard"],
        "result": result,
    }
    # The row was inserted as "queued" at enqueue time; update it in place.
    updated = await Scan.filter(id=scan_id).update(**values)
    if not updated:
        entry = SCANS.get(scan_id, {})
        values["kind"] = entry.get("kind", "full")
        values["scan_target"] = domain
        values["created_by"] = entry.get("created_by")
        await Scan.create(id=scan_id, **values)
    logger.info(f"[{scan_id}] Scan persisted (domain_id={dom.id})")

    # Delta notifications — best-effort, must never break the pipeline.
    try:
        await asyncio.to_thread(notify.notify_scan_completed, result, result.get("changes"))
    except Exception:
        logger.exception(f"[{scan_id}] Notification step failed")


async def _persist_failed_scan(scan_id: str, domain: str, domain_id: int | None, error: str) -> None:
    dom = await Domain.get_or_none(id=domain_id) if domain_id is not None else None
    if dom is None:
        dom = await _get_or_create_domain(None, domain)
    entry = SCANS.get(scan_id, {})
    values = {
        "domain_id": dom.id,
        "status": "failed",
        "progress": entry.get("progress", 0),
        "current_module": None,
        "started_at": datetime.fromisoformat(entry.get("started_at", datetime.now(timezone.utc).isoformat())),
        "completed_at": datetime.now(timezone.utc),
        "scorecard": None,
        "result": {"error": error},
    }
    updated = await Scan.filter(id=scan_id).update(**values)
    if not updated:
        values["kind"] = entry.get("kind", "full")
        values["scan_target"] = domain
        values["created_by"] = entry.get("created_by")
        await Scan.create(id=scan_id, **values)


def _create_scan_entry(
    domain: str,
    domain_id: int | None,
    agent_mode: bool = False,
    max_steps: int | None = None,
    extra_allowed: list[str] | None = None,
    created_by: int | None = None,
    kind: str = "full",
    skip_discovery: bool = False,
    modules: list[str] | None = None,
) -> str:
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "scan_id": scan_id,
        "domain": domain,
        "domain_id": domain_id,
        "status": "queued",
        "progress": 0,
        "current_module": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "result": None,
        "agent_mode": agent_mode,
        "max_steps": max_steps,
        "extra_allowed": extra_allowed or [],
        "created_by": created_by,
        "kind": kind,
        "skip_discovery": skip_discovery,
        "modules_allowlist": modules,
    }
    return scan_id


async def _insert_queued_scan(scan_id: str, domain: str, domain_id: int | None) -> None:
    """Persist the Scan row as 'queued' the moment it is enqueued, so a crash
    mid-scan leaves a trace the startup sweep can mark as 'interrupted'."""
    dom = await Domain.get_or_none(id=domain_id) if domain_id is not None else None
    if dom is None:
        dom = await _get_or_create_domain(None, domain)
    entry = SCANS[scan_id]
    await Scan.create(
        id=scan_id,
        domain=dom,
        kind=entry.get("kind", "full"),
        scan_target=domain,
        status="queued",
        progress=0,
        current_module=None,
        started_at=datetime.fromisoformat(entry["started_at"]),
        created_by=entry.get("created_by"),
    )


# ── Scheduler ──────────────────────────────────────────────────────────────────
async def _scheduler_loop() -> None:
    while True:
        try:
            now = datetime.now(timezone.utc)
            settings = await _load_settings()
            if settings.get("vuln_scan_enabled", True):
                due = await Schedule.filter(enabled=True, next_run_at__lte=now).select_related("domain")
                for sched in due:
                    company_domains = []
                    if sched.domain.company_id is not None:
                        company_domains = [
                            d.domain for d in await Domain.filter(company_id=sched.domain.company_id)
                        ]
                    scan_id = _create_scan_entry(
                        sched.domain.domain, sched.domain.id,
                        agent_mode=sched.agent_mode, extra_allowed=company_domains,
                    )
                    sched.last_run_at = now
                    sched.next_run_at = now + timedelta(hours=sched.interval_hours)
                    await sched.save()
                    await _insert_queued_scan(scan_id, sched.domain.domain, sched.domain.id)
                    await scan_queue.enqueue(scan_id, sched.domain.domain, sched.domain.id)
                    logger.info(f"Scheduler enqueued scan {scan_id} for {sched.domain.domain}")
            if settings.get("discovery_enabled", True):
                due_discover = await Schedule.filter(
                    discover_enabled=True,
                    discover_interval_hours__not_isnull=True,
                    next_discover_at__lte=now,
                ).select_related("domain")
                for sched in due_discover:
                    in_flight = any(
                        s.get("domain_id") == sched.domain.id and s["status"] in ("queued", "running")
                        for s in SCANS.values()
                    )
                    if in_flight:
                        # Don't pile up scans: push the next occurrence out and retry then.
                        sched.next_discover_at = now + timedelta(hours=sched.discover_interval_hours)
                        await sched.save()
                        continue
                    scan_id = _create_scan_entry(sched.domain.domain, sched.domain.id, kind="discover")
                    sched.next_discover_at = now + timedelta(hours=sched.discover_interval_hours)
                    await sched.save()
                    await _insert_queued_scan(scan_id, sched.domain.domain, sched.domain.id)
                    await scan_queue.enqueue(scan_id, sched.domain.domain, sched.domain.id)
                    logger.info(f"Scheduler enqueued discovery scan {scan_id} for {sched.domain.domain}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Scheduler iteration failed: {e}")
        await asyncio.sleep(60)


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Auth & users (RBAC) ────────────────────────────────────────────────────────
# Role matrix (enforced with AUTH_ENABLED=true; dev mode passes as admin):
#   viewer:   read-only — all GET endpoints (gated by AuthMiddleware)
#   operator: viewer + launch scans/discoveries, manage companies/domains/schedules
#   admin:    operator + deletes + /api/users CRUD
LOGIN_RATE_LIMIT_MAX = 10
_login_rate_hits: dict[str, list[float]] = {}

# Precomputed hash verified against when the account doesn't exist, so the
# login response time doesn't reveal whether the email is registered.
_DUMMY_PASSWORD_HASH = hash_password("timing-equalizer-not-a-real-password")


def _login_rate_limit_ok(ip: str) -> bool:
    return _rate_limit_check(ip, _login_rate_hits, LOGIN_RATE_LIMIT_MAX)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalize_email(v: str) -> str:
    v = v.strip().lower()
    if not EMAIL_RE.match(v):
        raise ValueError("invalid email address")
    return v


def _validate_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("password must be at least 8 characters")
    return v


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _normalize_email(v)


class BootstrapRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _normalize_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class UserCreateRequest(BaseModel):
    email: str
    password: str
    role: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _normalize_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        return v


class UserUpdateRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is not None and v not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        return _validate_password(v) if v is not None else None


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "active": user.active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _session_payload(user: User, token: str) -> dict:
    return {"token": token, "user": {"id": user.id, "email": user.email, "role": user.role}}


async def _active_admin_count(exclude_id: int | None = None) -> int:
    qs = User.filter(role="admin", active=True)
    if exclude_id is not None:
        qs = qs.exclude(id=exclude_id)
    return await qs.count()


@app.post("/api/auth/login")
async def login(request: LoginRequest, req: Request):
    client_ip = req.client.host if req.client else "unknown"
    if not _login_rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 logins per minute")
    user = await User.get_or_none(email=request.email)
    if user is None or not user.active:
        verify_password(request.password, _DUMMY_PASSWORD_HASH)  # timing equalizer
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.last_login_at = datetime.now(timezone.utc)
    await user.save()
    token = await issue_token(user)
    logger.info(f"User {user.email} logged in")
    return _session_payload(user, token)


@app.post("/api/auth/logout")
async def logout(req: Request):
    token = bearer_token(req.headers)
    if token:
        await revoke_token(token)
    return {"message": "Logged out"}


@app.get("/api/auth/me")
async def me(user=Depends(current_user)):
    if isinstance(user, User):
        return {"id": user.id, "email": user.email, "role": user.role}
    return DEV_USER  # dev mode: local admin


@app.get("/api/auth/bootstrap")
async def bootstrap_status():
    return {"needed": await User.all().count() == 0}


# Serializes the count-check + create so two concurrent bootstrap requests
# can't both pass the "no users yet" gate (single-process app: a lock suffices).
_bootstrap_lock = asyncio.Lock()


@app.post("/api/auth/bootstrap")
async def bootstrap(request: BootstrapRequest):
    async with _bootstrap_lock:
        if await User.all().count() > 0:
            raise HTTPException(status_code=403, detail="Bootstrap not available: users already exist")
        user = await User.create(
            email=request.email,
            password_hash=hash_password(request.password),
            role="admin",
        )
        token = await issue_token(user)
    logger.info(f"Bootstrap: created first admin {user.email}")
    return _session_payload(user, token)


# ── User management (admin only) ───────────────────────────────────────────────
@app.get("/api/users", dependencies=[Depends(require_role("admin"))])
async def list_users():
    users = await User.all().order_by("id")
    return [_user_payload(u) for u in users]


@app.post("/api/users", dependencies=[Depends(require_role("admin"))], status_code=201)
async def create_user(request: UserCreateRequest):
    if await User.get_or_none(email=request.email) is not None:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = await User.create(
        email=request.email,
        password_hash=hash_password(request.password),
        role=request.role,
    )
    return _user_payload(user)


@app.patch("/api/users/{user_id}", dependencies=[Depends(require_role("admin"))])
async def update_user(user_id: int, request: UserUpdateRequest):
    user = await User.get_or_none(id=user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    strips_admin = (
        (request.role is not None and request.role != "admin")
        or request.active is False
    )
    if strips_admin and user.role == "admin" and user.active \
            and await _active_admin_count(exclude_id=user.id) == 0:
        raise HTTPException(status_code=400, detail="Cannot demote or deactivate the last admin")
    if request.role is not None:
        user.role = request.role
    if request.active is not None:
        user.active = request.active
    if request.password is not None:
        user.password_hash = hash_password(request.password)
    await user.save()
    if request.password is not None or request.active is False:
        # Password change or deactivation invalidates existing sessions.
        await revoke_user_tokens(user.id)
    return _user_payload(user)


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, current=Depends(require_role("admin"))):
    if user_id_of(current) == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    user = await User.get_or_none(id=user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin" and user.active and await _active_admin_count(exclude_id=user.id) == 0:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    await user.delete()  # FK cascade removes their tokens
    return {"message": "Deleted"}


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, req: Request, user=Depends(require_role("operator", "admin"))):
    client_ip = req.client.host if req.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 scans per minute")
    if request.modules and request.agent_mode:
        raise HTTPException(status_code=422, detail="agent_mode is not allowed for module scans")

    domain_id = None
    extra_allowed: list[str] = []
    company_name = (request.company_name or "").strip()
    if company_name:
        company = await _get_or_create_company(company_name)
        dom = await _get_or_create_domain(company.id, request.domain)
        domain_id = dom.id
        extra_allowed = [d.domain for d in await Domain.filter(company_id=company.id)]

    settings = await _load_settings()
    kind = "module" if request.modules else "full"
    scan_id = _create_scan_entry(
        request.domain, domain_id,
        # Module scans never run the agent phase, regardless of the default.
        agent_mode=False if request.modules else
            (request.agent_mode
             if request.agent_mode is not None
             else settings["agent_mode_default"]),
        extra_allowed=extra_allowed,
        created_by=user_id_of(user),
        kind=kind,
        skip_discovery=(request.skip_discovery
            if request.skip_discovery is not None
            else settings["skip_discovery_default"]) if not request.modules else False,
        modules=request.modules,
    )
    await _insert_queued_scan(scan_id, request.domain, domain_id)
    await scan_queue.enqueue(scan_id, request.domain, domain_id)
    return ScanResponse(
        scan_id=scan_id,
        domain=request.domain,
        message="Scan started. Poll /api/scan/{scan_id} for status.",
    )


# ── Agent scan (sugar over POST /api/scan with agent_mode=true) ──────────────
@app.post("/api/agent-scan")
async def start_agent_scan(request: AgentScanRequest, req: Request, user=Depends(require_role("operator", "admin"))):
    if not os.getenv("AI_API_KEY"):
        raise HTTPException(status_code=503, detail="AI not configured — set AI_API_KEY")
    client_ip = req.client.host if req.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 scans per minute")

    domain_id = None
    extra_allowed: list[str] = []
    company_name = (request.company_name or "").strip()
    if company_name:
        company = await _get_or_create_company(company_name)
        dom = await _get_or_create_domain(company.id, request.domain)
        domain_id = dom.id
        extra_allowed = [d.domain for d in await Domain.filter(company_id=company.id)]

    scan_id = _create_scan_entry(
        request.domain, domain_id,
        agent_mode=True, max_steps=request.max_steps, extra_allowed=extra_allowed,
        created_by=user_id_of(user),
    )
    await _insert_queued_scan(scan_id, request.domain, domain_id)
    await scan_queue.enqueue(scan_id, request.domain, domain_id)
    return {"agent_scan_id": scan_id, "status": "running"}


# ── Host scan (manual, per inventoried host) ─────────────────────────────────
class HostScanRequest(BaseModel):
    host: str
    agent_mode: bool = False
    # Optional module allowlist (⊆ HOST_SCAN_MODULES) → kind="module" scan of
    # the host instead of the full host subset.
    modules: list[str] | None = None

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        # IPs and garbage fail the hostname regex → 422 before we hit the DB.
        return _normalize_domain(v)

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v: list[str] | None) -> list[str] | None:
        return _validate_modules_allowlist(v, HOST_SCAN_MODULES)


@app.post("/api/host-scan", response_model=ScanResponse)
async def start_host_scan(request: HostScanRequest, req: Request, user=Depends(require_role("operator", "admin"))):
    client_ip = req.client.host if req.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 scans per minute")
    if request.modules and request.agent_mode:
        raise HTTPException(status_code=422, detail="agent_mode is not allowed for module scans")
    host = request.host
    # The host must be the apex of a known Domain or an inventoried subdomain
    # asset of one — resolve the parent domain row either way.
    dom = await Domain.get_or_none(domain=host)
    if dom is None:
        asset = await Asset.filter(type="subdomain", value=host).first()
        if asset is not None:
            dom = await Domain.get_or_none(id=asset.domain_id)
    if dom is None:
        raise HTTPException(status_code=404, detail="Unknown host: not an inventoried domain or subdomain")
    scan_id = _create_scan_entry(
        host, dom.id,
        agent_mode=False if request.modules else request.agent_mode,
        created_by=user_id_of(user),
        kind="module" if request.modules else "host",
        modules=request.modules,
    )
    await _insert_queued_scan(scan_id, host, dom.id)
    await scan_queue.enqueue(scan_id, host, dom.id)
    logger.info(f"[{scan_id}] Host scan queued for {host} (parent domain {dom.domain})")
    return ScanResponse(
        scan_id=scan_id,
        domain=host,
        message="Host scan started. Poll /api/scan/{scan_id} for status.",
    )


def _agent_scan_payload(scan_id: str, domain: str, status: str, started_at: str | None,
                        result: dict | None, live_steps: list | None,
                        completed_at: str | None, error: str | None) -> dict:
    base = {
        "agent_scan_id": scan_id,
        "domain": domain,
        "started_at": started_at,
        "steps": live_steps if live_steps is not None else (result or {}).get("agent_steps", []),
    }
    if status in ("queued", "running"):
        return base | {"status": "running"}
    if status == "completed":
        result = result or {}
        return base | {
            "status": "completed",
            "final_summary": result.get("agent_summary"),
            "findings": [f for f in result.get("findings", []) if f.get("module") == "agent"],
            "assets_discovered": result.get("assets_discovered", 0),
            "completed_at": completed_at or result.get("completed_at"),
        }
    return base | {"status": "error", "error": error or f"scan {status}"}


@app.get("/api/agent-scan/{agent_scan_id}")
async def get_agent_scan(agent_scan_id: str):
    entry = SCANS.get(agent_scan_id)
    if entry is not None:
        return _agent_scan_payload(
            agent_scan_id, entry["domain"], entry["status"], entry["started_at"],
            entry.get("result"), entry.get("agent_steps"), entry.get("completed_at"),
            (entry.get("result") or {}).get("error") if entry["status"] == "failed" else None,
        )
    row = await Scan.filter(id=agent_scan_id).select_related("domain").first()
    if row is None:
        raise HTTPException(status_code=404, detail="Agent scan not found")
    result = row.result or {}
    return _agent_scan_payload(
        agent_scan_id, row.domain.domain, row.status,
        row.started_at.isoformat() if row.started_at else None,
        result, None,
        row.completed_at.isoformat() if row.completed_at else None,
        result.get("error") or result.get("agent_error") if row.status != "completed" else None,
    )


def _strip_secret_values(node: Any) -> Any:
    """Copy `node` dropping the full secret `value` from every secret object
    (they always carry a redacted `snippet` alongside). Used to serve scan
    results to viewers; the stored result keeps the value for operators/admins
    and the PDF flow. Returns new structures — the input is never mutated."""
    if isinstance(node, dict):
        return {
            k: _strip_secret_values(v)
            for k, v in node.items()
            if not (k == "value" and "snippet" in node)
        }
    if isinstance(node, list):
        return [_strip_secret_values(item) for item in node]
    return node


async def _scan_result_for_role(result: dict, req: Request) -> dict:
    """Scan result shaped for the caller's role. Viewers (and unresolvable
    users — fail closed) get secret values stripped; operators/admins and
    dev mode (AUTH_ENABLED=false) get the full result."""
    if not AUTH_ENABLED:
        return result
    token = bearer_token(req.headers)
    user = await resolve_token_user(token) if token else None
    role = getattr(user, "role", None)
    if role in ("operator", "admin"):
        return result
    return _strip_secret_values(result)


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str, req: Request):
    scan = SCANS.get(scan_id)
    if scan is not None:
        if scan["status"] != "completed":
            payload = {
                "scan_id": scan_id,
                "domain": scan["domain"],
                "status": scan["status"],
                "progress": scan["progress"],
                "current_module": scan["current_module"],
                "phase": "agent" if scan["current_module"] == "agent" else "scan",
                "kind": scan.get("kind", "full"),
            }
            if scan.get("started_at"):
                payload["started_at"] = scan["started_at"]
            if scan.get("planned_modules") is not None:
                payload["planned_modules"] = scan["planned_modules"]
            if scan.get("agent_steps") is not None:
                payload["agent_steps"] = scan["agent_steps"]
            return payload
        result = await _scan_result_for_role(scan["result"], req)
        return result | {"scan_id": scan_id, "status": "completed"}

    row = await Scan.filter(id=scan_id).select_related("domain").first()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.status == "completed" and row.result:
        result = await _scan_result_for_role(row.result, req)
        return result | {"scan_id": scan_id, "status": "completed"}
    return {
        "scan_id": scan_id,
        "domain": row.domain.domain,
        "status": row.status,
        "progress": row.progress,
        "current_module": row.current_module,
    }


@app.get("/api/scans")
async def list_scans(domain: str | None = Query(default=None)):
    rows: dict[str, dict] = {}
    db_scans = await Scan.all().select_related("domain").order_by("-started_at")
    wanted = domain.strip().lower() if domain else None
    for s in db_scans:
        target = s.scan_target or s.domain.domain
        # ?domain=<host> filters by actual scan target (host scans carry the
        # host in scan_target; legacy rows fall back to the apex domain).
        if wanted and target.lower() != wanted:
            continue
        rows[s.id] = {
            "scan_id": s.id,
            "domain": s.domain.domain,
            "target": target,
            "status": s.status,
            "progress": s.progress,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "grade": (s.scorecard or {}).get("grade"),
            "kind": s.kind or (s.result or {}).get("kind", "full"),
        }
    # Overlay in-flight scans (live progress)
    for s in SCANS.values():
        if s["status"] in ("queued", "running"):
            if wanted and s["domain"].lower() != wanted:
                continue
            rows[s["scan_id"]] = {
                "scan_id": s["scan_id"],
                "domain": s["domain"],
                "target": s["domain"],
                "status": s["status"],
                "progress": s["progress"],
                "started_at": s["started_at"],
                "completed_at": s.get("completed_at"),
                "grade": None,
                "kind": s.get("kind", "full"),
            }
    return list(rows.values())


@app.post("/api/scan/{scan_id}/stop", dependencies=[Depends(require_role("operator", "admin"))])
async def stop_scan(scan_id: str):
    """Request a graceful stop: the orchestrator checks the flag between modules
    and persists partial results as 'interrupted'. Queued scans are skipped by
    the worker when they surface."""
    scan = SCANS.get(scan_id)
    if scan is not None:
        if scan["status"] not in ("queued", "running"):
            raise HTTPException(status_code=409, detail="Scan is not running")
        scan["stop_requested"] = True
        logger.info(f"[{scan_id}] Stop requested by user")
        return {"message": "Stop requested — the scan will halt after the current module"}
    row = await Scan.get_or_none(id=scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.status in ("queued", "running"):
        row.status = "interrupted"
        await row.save()
        return {"message": "Scan marked as interrupted"}
    raise HTTPException(status_code=409, detail="Scan is not running")


@app.post("/api/scan/{scan_id}/restart")
async def restart_scan(scan_id: str, user=Depends(require_role("operator", "admin"))):
    """Enqueue a fresh scan with the same domain and agent settings."""
    mem = SCANS.get(scan_id)
    row = await Scan.filter(id=scan_id).select_related("domain").first()
    if mem is None and row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    domain = mem["domain"] if mem else row.domain.domain
    domain_id = (mem.get("domain_id") if mem else None) or (row.domain_id if row else None)
    agent_mode = bool(mem.get("agent_mode")) if mem else bool((row.result or {}).get("agent_steps"))
    extra_allowed = list(mem.get("extra_allowed") or []) if mem else []
    new_id = _create_scan_entry(domain, domain_id, agent_mode=agent_mode,
                                extra_allowed=extra_allowed, created_by=user_id_of(user))
    await _insert_queued_scan(new_id, domain, domain_id)
    await scan_queue.enqueue(new_id, domain, domain_id)
    logger.info(f"[{scan_id}] restarted as {new_id}")
    return ScanResponse(scan_id=new_id, domain=domain, message="Scan restarted. Poll /api/scan/{scan_id} for status.")


@app.delete("/api/scan/{scan_id}", dependencies=[Depends(require_role("admin"))])
async def delete_scan(scan_id: str):
    if scan_id in SCANS:
        del SCANS[scan_id]
        return {"message": "Deleted"}
    row = await Scan.get_or_none(id=scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    await row.delete()
    return {"message": "Deleted"}


@app.get("/api/scan/{scan_id}/report.pdf")
async def download_pdf(scan_id: str):
    """Generate and return a PDF report for a completed scan."""
    result = None
    domain = None
    scan = SCANS.get(scan_id)
    if scan is not None:
        if scan["status"] == "completed" and scan.get("result"):
            result = scan["result"]
            domain = scan["domain"]
    else:
        row = await Scan.filter(id=scan_id).select_related("domain").first()
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        if row.status == "completed" and row.result:
            result = row.result
            domain = row.domain.domain
    if result is None:
        raise HTTPException(status_code=409, detail="Scan not completed yet")
    try:
        report_data = result | {"scan_id": scan_id, "status": "completed"}
        pdf_bytes = pdf_report.generate_pdf(report_data)
        filename = f"sauron_{(domain or 'unknown').replace('/', '_')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error(f"PDF generation error for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed")


# ── Domain discovery (company name -> candidate domains) ─────────────────────
async def _run_discovery(discovery_id: str, company_name: str) -> None:
    try:
        candidates = await domain_discovery.run(company_name)
        DISCOVERIES[discovery_id].update(
            {
                "status": "completed",
                "company_name": company_name,
                "candidates": candidates,
                "searched_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        await _auto_register_discovered_domains(company_name, candidates)
    except Exception as e:
        logger.exception(f"[{discovery_id}] Discovery crashed for '{company_name}'")
        DISCOVERIES[discovery_id].update({"status": "error", "error": str(e)})


async def _auto_register_discovered_domains(company_name: str, candidates: list[dict]) -> None:
    """Post-discovery hook for auto_discover_domains: when a company was just
    created (name match, <5 min old) register its high-confidence candidates as
    company domains, each with the default schedule. Best-effort — never breaks
    the discovery itself."""
    try:
        settings = await _load_settings()
        if not settings["auto_discover_domains"]:
            return
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        company = await Company.get_or_none(name=company_name, created_at__gte=cutoff)
        if company is None:
            return
        interval = settings["default_interval_hours"]
        for cand in candidates or []:
            if not isinstance(cand, dict) or cand.get("confidence") != "high":
                continue
            domain = (cand.get("domain") or "").strip().lower()
            if not domain or not DOMAIN_RE.match(domain):
                continue
            if await Domain.get_or_none(company_id=company.id, domain=domain) is not None:
                continue
            dom = await Domain.create(company_id=company.id, domain=domain)
            discover_on = settings["discovery_enabled"]
            discover_interval = settings["default_discover_interval_hours"]
            await Schedule.create(
                domain_id=dom.id,
                interval_hours=interval,
                enabled=True,
                agent_mode=settings["agent_mode_default"],
                next_run_at=datetime.now(timezone.utc) + timedelta(hours=interval),
                discover_enabled=discover_on,
                discover_interval_hours=discover_interval if discover_on else None,
                next_discover_at=datetime.now(timezone.utc) + timedelta(hours=discover_interval) if discover_on else None,
            )
            logger.info(f"Auto-registered discovered domain {domain} for company "
                        f"{company.id} ({company.name}) with default schedule every {interval}h")
    except Exception:
        logger.exception(f"Auto-registration of discovered domains failed for '{company_name}'")


@app.post("/api/discover")
async def start_discovery(request: DiscoverRequest, req: Request, user=Depends(require_role("operator", "admin"))):
    client_ip = req.client.host if req.client else "unknown"
    if not _discover_rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded: max {DISCOVER_RATE_LIMIT_MAX} discoveries per minute")

    discovery_id = str(uuid.uuid4())
    DISCOVERIES[discovery_id] = {
        "discovery_id": discovery_id,
        "status": "running",
        "company_name": request.company_name,
        "candidates": None,
        "searched_at": None,
        "created_by": user_id_of(user),
    }
    asyncio.create_task(_run_discovery(discovery_id, request.company_name))
    logger.info(f"[{discovery_id}] Discovery started for '{request.company_name}'")
    return {"discovery_id": discovery_id, "status": "running"}


@app.get("/api/discover/{discovery_id}")
async def get_discovery(discovery_id: str):
    discovery = DISCOVERIES.get(discovery_id)
    if discovery is None:
        raise HTTPException(status_code=404, detail="Discovery not found")
    if discovery["status"] == "running":
        return {"discovery_id": discovery_id, "status": "running"}
    if discovery["status"] == "error":
        return {"discovery_id": discovery_id, "status": "error", "error": discovery.get("error")}
    return {
        "discovery_id": discovery_id,
        "status": "completed",
        "company_name": discovery["company_name"],
        "candidates": discovery["candidates"],
        "searched_at": discovery["searched_at"],
    }


# ── Companies & domains ────────────────────────────────────────────────────────
@app.post("/api/companies", dependencies=[Depends(require_role("operator", "admin"))])
async def create_company(request: CompanyCreateRequest):
    existing = await Company.get_or_none(name=request.name)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Company already exists")
    company = await Company.create(name=request.name)
    settings = await _load_settings()
    discovery_id = None
    if settings["auto_discover_domains"]:
        # Same flow as POST /api/discover; on completion the post-discovery hook
        # auto-registers high-confidence candidates as this company's domains.
        discovery_id = str(uuid.uuid4())
        DISCOVERIES[discovery_id] = {
            "discovery_id": discovery_id,
            "status": "running",
            "company_name": request.name,
            "candidates": None,
            "searched_at": None,
            "created_by": None,
        }
        asyncio.create_task(_run_discovery(discovery_id, request.name))
        logger.info(f"[{discovery_id}] Auto-discovery started for new company '{request.name}'")
    return {"id": company.id, "name": company.name, "created_at": company.created_at,
            "discovery_id": discovery_id}


@app.get("/api/companies")
async def list_companies():
    companies = await Company.all().order_by("name")
    out = []
    for c in companies:
        domains = await Domain.filter(company_id=c.id).order_by("domain")
        dom_list = []
        for d in domains:
            latest = await Scan.filter(domain_id=d.id, status="completed",
                                       kind__in=["full", "discover"]) \
                .order_by("-completed_at", "-started_at").first()
            schedule = await Schedule.get_or_none(domain_id=d.id)
            dom_list.append({
                "id": d.id,
                "domain": d.domain,
                "created_at": d.created_at,
                "app_developers": d.app_developers or [],
                "last_grade": (latest.scorecard or {}).get("grade") if latest else None,
                "last_scan_at": latest.completed_at if latest else None,
                "schedule": {
                    "interval_hours": schedule.interval_hours,
                    "enabled": schedule.enabled,
                    "agent_mode": schedule.agent_mode,
                    "next_run_at": schedule.next_run_at,
                    "discover_enabled": schedule.discover_enabled,
                    "discover_interval_hours": schedule.discover_interval_hours,
                    "next_discover_at": schedule.next_discover_at,
                } if schedule else None,
            })
        out.append({
            "id": c.id,
            "name": c.name,
            "created_at": c.created_at,
            "domains": dom_list,
            "assets_count": await Asset.filter(domain_id__in=[d.id for d in domains]).count() if domains else 0,
        })
    return out


@app.post("/api/companies/{company_id}/domains", dependencies=[Depends(require_role("operator", "admin"))])
async def create_domain(company_id: int, request: DomainCreateRequest):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    existing = await Domain.get_or_none(company_id=company.id, domain=request.domain)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Domain already registered for this company")
    dom = await Domain.create(company_id=company.id, domain=request.domain)

    # New domains inherit the default recurrence from settings so the whole
    # fleet is scheduled by default (editable per domain afterwards).
    settings = await _load_settings()
    interval = settings["default_interval_hours"]
    discover_on = settings["discovery_enabled"]
    discover_interval = settings["default_discover_interval_hours"]
    now = datetime.now(timezone.utc)
    await Schedule.create(
        domain_id=dom.id,
        interval_hours=interval,
        enabled=True,
        agent_mode=settings["agent_mode_default"],
        next_run_at=now + timedelta(hours=interval),
        discover_enabled=discover_on,
        discover_interval_hours=discover_interval if discover_on else None,
        next_discover_at=now + timedelta(hours=discover_interval) if discover_on else None,
    )
    logger.info(f"Domain {dom.domain} added to company {company.id} with default schedule every {interval}h"
                f" (agent_mode={settings['agent_mode_default']}, discovery={discover_on} every {discover_interval}h)")
    return {"id": dom.id, "company_id": company.id, "domain": dom.domain, "created_at": dom.created_at}


@app.delete("/api/domains/{domain_id}", dependencies=[Depends(require_role("admin"))])
async def delete_domain(domain_id: int):
    dom = await Domain.get_or_none(id=domain_id)
    if dom is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    await dom.delete()  # FK cascade removes schedules/scans/subdomains/endpoints
    return {"message": "Deleted"}


@app.delete("/api/companies/{company_id}", dependencies=[Depends(require_role("admin"))])
async def delete_company(company_id: int):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    # Refuse to delete while any of its domains has a scan in flight
    busy = [s["domain"] for s in SCANS.values()
            if s["status"] in ("queued", "running") and s.get("domain_id")
            and await Domain.filter(id=s["domain_id"], company_id=company_id).exists()]
    if busy:
        raise HTTPException(status_code=409, detail=f"Scans in flight for: {', '.join(busy)} — wait or delete them first")
    await company.delete()  # FK cascade removes domains → scans/assets/schedules
    logger.info(f"Company {company_id} ({company.name}) deleted")
    return {"message": "Deleted"}


async def _build_company_findings(company: Company) -> dict:
    domains = await Domain.filter(company_id=company.id).order_by("domain")
    out_domains: list[dict] = []
    for d in domains:
        latest = await Scan.filter(domain_id=d.id, status="completed",
                                   kind__in=["full", "discover"]).order_by("-completed_at", "-started_at").first()
        if latest is None or not latest.result:
            out_domains.append({"domain": d.domain, "scan_id": None, "grade": None, "score": None,
                                "completed_at": None, "findings": []})
            continue
        result = latest.result or {}
        scorecard = latest.scorecard or {}
        out_domains.append({
            "domain": d.domain,
            "scan_id": latest.id,
            "grade": scorecard.get("grade"),
            "score": scorecard.get("score"),
            "overall_risk": scorecard.get("overall_risk"),
            "completed_at": latest.completed_at,
            "findings": result.get("findings") or [],
        })
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in out_domains:
        for f in d["findings"]:
            r = f.get("risk", "low")
            if r in counts:
                counts[r] += 1
    return {
        "company_id": company.id,
        "company_name": company.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": counts,
        "domains": out_domains,
    }


@app.get("/api/companies/{company_id}/findings")
async def company_findings(company_id: int):
    """Consolidated findings per company: for each domain, the findings of its
    latest completed scan, with the scan_id so the UI can drill into the report."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return await _build_company_findings(company)


# ── Remediation tracking & compliance mapping ─────────────────────────────────
FINDING_STATUSES = {"open", "accepted", "fixed"}


def _serialize_finding(rec: Finding) -> dict:
    return {
        "id": rec.id,
        "module": rec.module,
        "text": rec.text,
        "risk": rec.risk,
        "category": rec.category,
        "frameworks": rec.frameworks or [],
        "status": rec.status,
        "notes": rec.notes or "",
        "first_seen_scan_id": rec.first_seen_scan_id,
        "last_seen_scan_id": rec.last_seen_scan_id,
        "first_seen_at": rec.first_seen_at.isoformat() if rec.first_seen_at else None,
        "last_seen_at": rec.last_seen_at.isoformat() if rec.last_seen_at else None,
        "fixed_at": rec.fixed_at.isoformat() if rec.fixed_at else None,
    }


async def _company_findings_records(company_id: int) -> tuple[list[Domain], list[Finding]]:
    domains = await Domain.filter(company_id=company_id).order_by("domain")
    if not domains:
        return [], []
    records = await Finding.filter(domain_id__in=[d.id for d in domains])
    return domains, records


@app.get("/api/companies/{company_id}/remediations")
async def company_remediations(company_id: int):
    """Persistent findings grouped by domain with lifecycle status, plus
    company-wide counts by status and by risk (open findings only)."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    domains, records = await _company_findings_records(company_id)
    risk_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    by_domain: dict[int, list[dict]] = {d.id: [] for d in domains}
    totals = {
        "open": 0, "accepted": 0, "fixed": 0,
        "by_risk": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "auto_fixed_week": 0,
    }
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    for rec in records:
        serialized = _serialize_finding(rec)
        if rec.domain_id in by_domain:
            by_domain[rec.domain_id].append(serialized)
        if rec.status in ("open", "accepted", "fixed"):
            totals[rec.status] += 1
        if rec.status == "open" and rec.risk in totals["by_risk"]:
            totals["by_risk"][rec.risk] += 1
        if rec.status == "fixed" and rec.fixed_at and rec.fixed_at >= week_ago:
            totals["auto_fixed_week"] += 1
    out_domains = []
    for d in domains:
        items = sorted(
            by_domain[d.id],
            key=lambda f: (risk_rank.get(f["risk"], 9), f["status"] != "open", f["text"]),
        )
        counts = {"open": 0, "accepted": 0, "fixed": 0}
        for f in items:
            counts[f["status"]] = counts.get(f["status"], 0) + 1
        out_domains.append({"domain": d.domain, "counts": counts, "findings": items})
    return {
        "company_id": company.id,
        "company_name": company.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": totals,
        "domains": out_domains,
    }


class FindingStatusUpdate(BaseModel):
    status: str
    notes: str | None = None


@app.put("/api/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: int,
    request: FindingStatusUpdate,
    user=Depends(require_role("operator", "admin")),
):
    """Lifecycle transition of a persistent finding. `fixed` stamps fixed_at;
    reopening (`open`) clears it. Notes are optional and only replaced when
    provided."""
    status = (request.status or "").strip().lower()
    if status not in FINDING_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{request.status}' — expected one of {sorted(FINDING_STATUSES)}",
        )
    rec = await Finding.get_or_none(id=finding_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    rec.status = status
    if status == "fixed":
        if rec.fixed_at is None:
            rec.fixed_at = datetime.now(timezone.utc)
    elif status == "open":
        rec.fixed_at = None
    if request.notes is not None:
        rec.notes = request.notes
    await rec.save()
    logger.info(f"Finding #{rec.id} status -> {status} by {getattr(user, 'email', user)}")
    return _serialize_finding(rec)


@app.get("/api/companies/{company_id}/compliance")
async def company_compliance(company_id: int):
    """Framework coverage matrix: for each compliance framework, the open
    findings by severity and the historical fixed/total ratio (progress)."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    _, records = await _company_findings_records(company_id)
    matrix: dict[str, dict] = {
        fw: {
            "framework": fw,
            "open": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "accepted": 0,
            "fixed": 0,
            "total": 0,
        }
        for fw in compliance.FRAMEWORKS
    }
    untagged = {"open": 0, "total": 0}
    for rec in records:
        frameworks = rec.frameworks or []
        if not frameworks:
            untagged["total"] += 1
            if rec.status == "open":
                untagged["open"] += 1
        for fw in frameworks:
            cell = matrix.get(fw)
            if cell is None:
                continue
            cell["total"] += 1
            if rec.status == "open":
                cell["open"]["total"] += 1
                if rec.risk in cell["open"]:
                    cell["open"][rec.risk] += 1
            elif rec.status == "fixed":
                cell["fixed"] += 1
            elif rec.status == "accepted":
                cell["accepted"] += 1
    return {
        "company_id": company.id,
        "company_name": company.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": list(matrix.values()),
        "untagged": untagged,
    }


@app.get("/api/companies/{company_id}/rating-history")
async def company_rating_history(company_id: int):
    """Score/grade over time per domain of the company — feeds the trend chart."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    points: list[dict] = []
    domains = await Domain.filter(company_id=company_id)
    for d in domains:
        scans = await Scan.filter(domain_id=d.id, status="completed",
                                  kind__in=["full", "discover"]).order_by("completed_at", "started_at")
        for s in scans:
            sc = s.scorecard or {}
            if sc.get("score") is None:
                continue
            points.append({
                "domain": d.domain,
                "scan_id": s.id,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "score": sc.get("score"),
                "grade": sc.get("grade"),
                "overall_risk": sc.get("overall_risk"),
            })
    points.sort(key=lambda p: p["completed_at"] or "")
    return {"company_id": company_id, "company_name": company.name, "points": points}


@app.get("/api/companies/{company_id}/report.pdf")
async def company_report_pdf(company_id: int):
    """Consolidated PDF report for a company: cover with totals, one section per
    domain (latest completed scan) and an aggregated asset-inventory summary."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    findings_payload = await _build_company_findings(company)
    scanned = [d for d in findings_payload["domains"] if d.get("scan_id")]
    if not scanned:
        raise HTTPException(status_code=409, detail="No completed scans in any domain of this company")
    try:
        assets_payload = await _build_company_assets(company)
        assets_summary = assets_payload.get("summary")
    except Exception as e:
        logger.warning(f"Company PDF: asset inventory unavailable for company {company_id}: {e}")
        assets_summary = None
    try:
        pdf_bytes = pdf_report.generate_company_pdf(
            company.name, findings_payload["domains"], assets_summary,
        )
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", company.name).strip("_") or "company"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="sauron_{safe_name}.pdf"'},
        )
    except Exception as e:
        logger.error(f"Company PDF generation error for {company_id}: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed")


# ── Company asset inventory ────────────────────────────────────────────────────
async def _surface_thresholds(domains: list[Domain]) -> tuple[dict[int, datetime], dict[int, str]]:
    """Shared current-surface rule: hide an asset only when there is enough
    history to judge (≥2 completed scans) AND its last sighting predates the
    2nd-last completed one. Returns (threshold_by_domain, last_scan_id_by_domain).
    Used by both the dashboard builder and the portfolio assets_count so the
    numbers always agree."""
    surface_since: dict[int, datetime] = {}
    last_scan_by_domain: dict[int, str] = {}
    for d in domains:
        recent = await Scan.filter(domain_id=d.id, status="completed",
                                   kind__in=["full", "discover"]) \
            .order_by("-completed_at", "-started_at").limit(2)
        if len(recent) >= 2:
            surface_since[d.id] = recent[-1].completed_at or recent[-1].started_at
        if recent:
            last_scan_by_domain[d.id] = recent[0].id
    return surface_since, last_scan_by_domain


async def _build_company_assets(company: Company) -> dict:
    domains = await Domain.filter(company_id=company.id).order_by("domain")
    dom_names = {d.id: d.domain for d in domains}
    surface_since, last_scan_by_domain = await _surface_thresholds(domains)

    assets = await Asset.filter(domain_id__in=list(dom_names)).order_by("type", "value") if dom_names else []

    grouped: dict[str, list[dict]] = {
        "subdomains": [], "ips": [], "endpoints": [],
        "technologies": [], "admin_panels": [], "exposed_files": [],
        "ports": [], "apps": [], "neighbors": [],
    }
    port_count = 0
    new_last_cycle = 0

    for asset in assets:
        threshold = surface_since.get(asset.domain_id)
        if threshold and asset.last_seen_at and asset.last_seen_at < threshold:
            continue  # not seen since the 2nd-last completed scan — no longer current surface
        meta = asset.metadata or {}
        is_new = asset.first_seen_scan_id == last_scan_by_domain.get(asset.domain_id)
        if is_new:
            new_last_cycle += 1
        base = {
            "id": asset.id,
            "value": asset.value,
            "domain": dom_names.get(asset.domain_id, ""),
            "first_seen": asset.first_seen_at.isoformat() if asset.first_seen_at else None,
            "last_seen": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
            "is_new": is_new,
        }
        if asset.type == "subdomain":
            grouped["subdomains"].append(base | {
                "ips": meta.get("ips") or [],
                "http_status": meta.get("http_status"),
            })
        elif asset.type == "ip":
            # IpAsset has no per-asset domain key — it aggregates hostnames
            grouped["ips"].append({
                "value": asset.value,
                "domains": meta.get("domains") or [],
                "open_ports": meta.get("open_ports") or [],
                "first_seen": base["first_seen"],
                "last_seen": base["last_seen"],
                "is_new": is_new,
            })
        elif asset.type == "endpoint":
            grouped["endpoints"].append(base | {"source": meta.get("source") or ""})
        elif asset.type == "technology":
            grouped["technologies"].append(base | {"category": meta.get("category") or "other"})
        elif asset.type == "admin_panel":
            grouped["admin_panels"].append(base | {"http_status": meta.get("http_status")})
        elif asset.type == "exposed_file":
            grouped["exposed_files"].append(base | {"risk": meta.get("risk") or "low"})
        elif asset.type == "port":
            ip, _, port = asset.value.partition(":")
            grouped["ports"].append(base | {
                "ip": ip,
                "port": int(port) if port.isdigit() else None,
                "service": meta.get("service"),
            })
            port_count += 1
        elif asset.type == "app":
            grouped["apps"].append(base | {
                "store": meta.get("store"),
                "os": meta.get("os"),
                "version": meta.get("version"),
                "developer": meta.get("developer"),
                "url": meta.get("url"),
                "updated": meta.get("updated"),
                "llm_verdict": meta.get("llm_verdict"),
                "official_developer": bool(meta.get("official_developer")),
                "suspicious": bool(meta.get("suspicious")),
            })
        elif asset.type == "neighbor":
            grouped["neighbors"].append(base | {
                "ip": meta.get("ip"),
                "neighbor_of": meta.get("neighbor_of"),
            })

    return {
        "company_id": company.id,
        "company_name": company.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "domains": len(domains),
            "subdomains": len(grouped["subdomains"]),
            "ips": len(grouped["ips"]),
            "endpoints": len(grouped["endpoints"]),
            "technologies": len(grouped["technologies"]),
            "admin_panels": len(grouped["admin_panels"]),
            "exposed_files": len(grouped["exposed_files"]),
            "open_ports": port_count,
            "apps": len(grouped["apps"]),
            "neighbors": len(grouped["neighbors"]),
            "new_last_cycle": new_last_cycle,
        },
        "assets": grouped,
    }


@app.get("/api/companies/{company_id}/assets")
async def company_assets(company_id: int):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return await _build_company_assets(company)


# ── Asset review workflow (suspicious discoveries) ────────────────────────────
class AssetReviewRequest(BaseModel):
    action: str  # "approve" | "reject"


class AssetBulkReviewRequest(BaseModel):
    type: str
    action: str  # "approve" | "reject"
    only_suspicious: bool = True


@app.delete("/api/assets/{asset_id}", dependencies=[Depends(require_role("operator", "admin"))])
async def delete_asset(asset_id: int):
    asset = await Asset.get_or_none(id=asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    await asset.delete()
    return {"message": "Deleted"}


@app.post("/api/assets/{asset_id}/review", dependencies=[Depends(require_role("operator", "admin"))])
async def review_asset(asset_id: int, request: AssetReviewRequest):
    """Approve a suspicious asset (mark official, keep monitoring) or reject it
    (delete the row)."""
    action = (request.action or "").strip().lower()
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Invalid action — expected 'approve' or 'reject'")
    asset = await Asset.get_or_none(id=asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if action == "reject":
        await asset.delete()
        return {"message": "Deleted"}
    meta = dict(asset.metadata or {})
    meta["suspicious"] = False
    meta["llm_verdict"] = "official"
    asset.metadata = meta
    await asset.save()
    return {"id": asset.id, "metadata": asset.metadata}


@app.post("/api/companies/{company_id}/assets/review-bulk", dependencies=[Depends(require_role("operator", "admin"))])
async def review_assets_bulk(company_id: int, request: AssetBulkReviewRequest):
    """Bulk review of a company's assets of one type (e.g. reject every app the
    LLM flagged as suspicious)."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    action = (request.action or "").strip().lower()
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Invalid action — expected 'approve' or 'reject'")
    candidates = await Asset.filter(domain__company_id=company_id, type=request.type)
    if request.only_suspicious:
        candidates = [a for a in candidates if (a.metadata or {}).get("suspicious")]
    if action == "reject":
        ids = [a.id for a in candidates]
        if ids:
            await Asset.filter(id__in=ids).delete()
        logger.info(f"Bulk review: rejected {len(ids)} '{request.type}' assets of company {company_id}")
        return {"deleted": len(ids)}
    updated = 0
    for asset in candidates:
        meta = dict(asset.metadata or {})
        meta["suspicious"] = False
        meta["llm_verdict"] = "official"
        asset.metadata = meta
        await asset.save()
        updated += 1
    logger.info(f"Bulk review: approved {updated} '{request.type}' assets of company {company_id}")
    return {"updated": updated}


# ── Host-centric inventory view ──────────────────────────────────────────────
# ACTIVO = host (apex domain | subdomain | ip); technologies, ports, endpoints,
# admin panels, exposed files and neighbors are ATTRIBUTES of the host. Built
# from the existing Asset rows — no DB model changes. Apex-level modules
# (tech fingerprint, JS endpoint mining, admin discovery, exposed files) probe
# the apex, so their assets attach to the apex host unless the value/URL points
# at another already-known subdomain.
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_NAMES = {0: "low", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _sev_rank(value: str | None) -> int:
    return _SEV_ORDER.get((value or "").strip().lower(), 0)


def _url_hostname(raw: str | None) -> str | None:
    """Hostname out of a URL-ish value; tolerates a missing scheme."""
    if not raw:
        return None
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return None
    return host.lower() if host else None


async def _collect_company_hosts(company: Company) -> dict:
    """Assemble the host-centric inventory. Returns the serializable payload
    plus an internal index (host key -> owning domain_id + contributing Asset
    rows) reused by the host-detail endpoint."""
    domains = await Domain.filter(company_id=company.id).order_by("domain")
    dom_names = {d.id: d.domain for d in domains}
    surface_since, last_scan_by_domain = await _surface_thresholds(domains)

    assets = await Asset.filter(domain_id__in=list(dom_names)).order_by("type", "value") if dom_names else []
    current: list[Asset] = []
    for a in assets:
        threshold = surface_since.get(a.domain_id)
        if threshold and a.last_seen_at and a.last_seen_at < threshold:
            continue  # same current-surface rule as _build_company_assets
        current.append(a)

    apex_of_domain = {d.id: d.domain.lower() for d in domains}
    hosts: dict[str, dict] = {}
    host_domain: dict[str, int] = {}
    host_assets: dict[str, list[Asset]] = {}
    risk_rank: dict[str, int] = {}

    def bump_risk(key: str, severity: str | None) -> None:
        rank = _sev_rank(severity)
        if rank > risk_rank.get(key, 0):
            risk_rank[key] = rank

    def ensure_host(kind: str, value: str, domain_id: int | None) -> tuple[str, dict]:
        key = value.lower()
        host = hosts.get(key)
        if host is None:
            host = hosts[key] = {
                "kind": kind,
                "value": value,
                "domain": dom_names.get(domain_id, "") if domain_id else "",
                "ips": [],
                "http_status": None,
                "first_seen": None,
                "last_seen": None,
                "is_new": False,
                "technologies": [],
                "open_ports": [],
                "endpoints": [],
                "admin_panels": [],
                "exposed_files": [],
                "apps": [],
                "neighbors": [],
                "risk": "low",
            }
            if domain_id is not None:
                host_domain[key] = domain_id
        return key, host

    def seen(host: dict, asset: Asset) -> None:
        first = asset.first_seen_at.isoformat() if asset.first_seen_at else None
        last = asset.last_seen_at.isoformat() if asset.last_seen_at else None
        if first and (host["first_seen"] is None or first < host["first_seen"]):
            host["first_seen"] = first
        if last and (host["last_seen"] is None or last > host["last_seen"]):
            host["last_seen"] = last

    known_subs: dict[int, set[str]] = {}
    sub_assets: list[Asset] = []
    ip_assets: list[Asset] = []
    attr_assets: list[Asset] = []
    app_count = 0
    neighbor_assets: list[Asset] = []
    for a in current:
        if a.type == "subdomain":
            sub_assets.append(a)
            known_subs.setdefault(a.domain_id, set()).add(a.value.lower())
        elif a.type == "ip":
            ip_assets.append(a)
        elif a.type in ("technology", "endpoint", "admin_panel", "exposed_file", "port"):
            attr_assets.append(a)
        elif a.type == "app":
            app_count += 1
        elif a.type == "neighbor":
            neighbor_assets.append(a)

    # 1) apex domain hosts first (exist even without assets) — the subdomain
    # enum often reports the apex itself as a subdomain entry; creating apexes
    # first makes those rows merge into the "domain" host instead of
    # duplicating it as a "subdomain".
    for d in domains:
        ensure_host("domain", d.domain, d.id)

    # 2) subdomain hosts
    for a in sub_assets:
        meta = a.metadata or {}
        key, host = ensure_host("subdomain", a.value, a.domain_id)
        host_assets.setdefault(key, []).append(a)
        host["ips"] = sorted(set(host["ips"]) | set(meta.get("ips") or []))
        if meta.get("http_status") is not None:
            host["http_status"] = meta.get("http_status")
        seen(host, a)
        if a.first_seen_scan_id == last_scan_by_domain.get(a.domain_id):
            host["is_new"] = True
        if meta.get("sensitive"):
            bump_risk(key, "medium")

    # 3) ip hosts — the same ip may appear under several company domains: merge
    for a in ip_assets:
        meta = a.metadata or {}
        key, host = ensure_host("ip", a.value, a.domain_id)
        host_assets.setdefault(key, []).append(a)
        seen(host, a)
        if a.first_seen_scan_id == last_scan_by_domain.get(a.domain_id):
            host["is_new"] = True
        existing_ports = {(p.get("port"), p.get("service")) for p in host["open_ports"]}
        for p in meta.get("open_ports") or []:
            if isinstance(p, dict) and p.get("port") and (p.get("port"), p.get("service")) not in existing_ports:
                host["open_ports"].append({"port": p["port"], "service": p.get("service")})

    # ip -> hostnames + ports, to wire resolution and roll ports up to name hosts
    ip_ports: dict[str, list[dict]] = {}
    ip_names: dict[str, set[str]] = {}
    for a in ip_assets:
        meta = a.metadata or {}
        ip_ports[a.value] = [
            {"port": p["port"], "service": p.get("service")}
            for p in meta.get("open_ports") or []
            if isinstance(p, dict) and p.get("port")
        ]
        ip_names.setdefault(a.value, set()).update(meta.get("domains") or [])
    # port-type rows ("ip:port") as a fallback source of port knowledge
    for a in attr_assets:
        if a.type != "port":
            continue
        ip, _, port = a.value.partition(":")
        if ip and port.isdigit():
            entry = {"port": int(port), "service": (a.metadata or {}).get("service")}
            if entry not in ip_ports.setdefault(ip, []):
                ip_ports[ip].append(entry)

    def target_host_key(domain_id: int, url_host: str | None) -> str:
        """Attribute an apex-level asset: known subdomain if the URL hostname
        matches one, otherwise the apex of its domain."""
        apex = apex_of_domain.get(domain_id, "")
        if url_host and url_host in known_subs.get(domain_id, set()):
            return url_host
        return apex

    # 4) attribute assets
    for a in attr_assets:
        meta = a.metadata or {}
        if a.type == "port":
            continue  # already folded into ip_ports
        if a.type == "technology":
            key = apex_of_domain.get(a.domain_id, "")
            if key in hosts:
                hosts[key]["technologies"].append({"name": a.value, "category": meta.get("category") or "other"})
                host_assets.setdefault(key, []).append(a)
        elif a.type == "endpoint":
            key = apex_of_domain.get(a.domain_id, "")
            if key in hosts:
                hosts[key]["endpoints"].append({"path": a.value, "source": meta.get("source") or ""})
                host_assets.setdefault(key, []).append(a)
        elif a.type == "admin_panel":
            key = target_host_key(a.domain_id, _url_hostname(a.value))
            if key in hosts:
                hosts[key]["admin_panels"].append({
                    "url": a.value,
                    "http_status": meta.get("http_status"),
                    "severity": meta.get("severity"),
                })
                host_assets.setdefault(key, []).append(a)
                bump_risk(key, meta.get("severity"))
        elif a.type == "exposed_file":
            key = target_host_key(a.domain_id, _url_hostname(meta.get("url")))
            if key in hosts:
                hosts[key]["exposed_files"].append({
                    "path": a.value,
                    "risk": meta.get("risk") or "low",
                    "url": meta.get("url"),
                    "description": meta.get("description"),
                })
                host_assets.setdefault(key, []).append(a)
                bump_risk(key, meta.get("risk"))

    # 5) neighbors hang from the ip they share
    unattributed_neighbors = 0
    for a in neighbor_assets:
        meta = a.metadata or {}
        ip = meta.get("ip")
        key = (ip or "").lower()
        if ip and key in hosts:
            hosts[key]["neighbors"].append({"domain": a.value, "neighbor_of": meta.get("neighbor_of")})
            host_assets.setdefault(key, []).append(a)
        else:
            unattributed_neighbors += 1

    # 6) wire ips and roll open ports up from resolved ips to name hosts
    apex_keys = set(apex_of_domain.values())
    sub_key_set = {s.lower() for subs in known_subs.values() for s in subs}
    for ip, names in ip_names.items():
        for name in names:
            nkey = name.lower()
            if nkey in hosts and hosts[nkey]["kind"] in ("domain", "subdomain"):
                if ip not in hosts[nkey]["ips"]:
                    hosts[nkey]["ips"].append(ip)
    for key, host in hosts.items():
        if host["kind"] == "ip":
            continue
        merged = {(p.get("port"), p.get("service")): p for p in host["open_ports"]}
        for ip in host["ips"]:
            for p in ip_ports.get(ip, []):
                merged.setdefault((p.get("port"), p.get("service")), p)
        host["open_ports"] = sorted(merged.values(), key=lambda p: p["port"])
        host["ips"].sort()

    # 7) risk per host + final ordering (riskiest first, then alphabetical)
    for key, host in hosts.items():
        host["risk"] = _SEV_NAMES[risk_rank.get(key, 0)]
    ordered = sorted(hosts.values(), key=lambda h: (-risk_rank.get(h["value"].lower(), 0), h["value"]))

    open_port_count = len({(ip, p["port"]) for ip, ports in ip_ports.items() for p in ports})
    summary = {
        "hosts": len(hosts),
        "ips": len([h for h in hosts.values() if h["kind"] == "ip"]),
        "open_ports": open_port_count,
        "endpoints": sum(len(h["endpoints"]) for h in hosts.values()),
        "technologies": sum(len(h["technologies"]) for h in hosts.values()),
        "admin_panels": sum(len(h["admin_panels"]) for h in hosts.values()),
        "exposed_files": sum(len(h["exposed_files"]) for h in hosts.values()),
        "apps": app_count,
        "neighbors": len(neighbor_assets) - unattributed_neighbors,
        "new_last_cycle": sum(1 for h in hosts.values() if h["is_new"]),
    }
    return {
        "payload": {
            "company_id": company.id,
            "company_name": company.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hosts": ordered,
            "summary": summary,
        },
        "host_domain": host_domain,
        "host_assets": host_assets,
        "domains": domains,
    }


async def _build_company_hosts(company: Company) -> dict:
    return (await _collect_company_hosts(company))["payload"]


@app.get("/api/companies/{company_id}/hosts")
async def company_hosts(company_id: int):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return await _build_company_hosts(company)


@app.get("/api/companies/{company_id}/hosts/{host_value}")
async def company_host_detail(company_id: int, host_value: str):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    collected = await _collect_company_hosts(company)
    key = host_value.lower()
    host = next((h for h in collected["payload"]["hosts"] if h["value"].lower() == key), None)
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found in this company's inventory")

    domain_id = collected["host_domain"].get(key)
    related = collected["host_assets"].get(key, [])
    asset_ids = [a.id for a in related]

    # Change history from AssetHistory, expanded field-by-field (newest first).
    history: list[dict] = []
    if asset_ids:
        rows = await AssetHistory.filter(asset_id__in=asset_ids).order_by("-changed_at", "-id").limit(200)
        type_by_id = {a.id: a for a in related}
        for row in rows:
            asset = type_by_id.get(row.asset_id)
            old_meta, new_meta = row.old_metadata or {}, row.new_metadata or {}
            for field in sorted((set(old_meta) | set(new_meta)) - {"ports_scanned"}):
                if old_meta.get(field) == new_meta.get(field):
                    continue
                history.append({
                    "changed_at": row.changed_at.isoformat() if row.changed_at else None,
                    "scan_id": row.scan_id,
                    "asset_type": asset.type if asset else "",
                    "asset_value": asset.value if asset else "",
                    "field": field,
                    "old": old_meta.get(field),
                    "new": new_meta.get(field),
                })

    # Recent scans of the parent domain + findings that mention this host.
    # Host scans are excluded here — the asset detail lists them separately.
    recent_scans: list[dict] = []
    related_findings: list[dict] = []
    if domain_id is not None:
        scans = await Scan.filter(domain_id=domain_id, status="completed",
                                  kind__in=["full", "discover"]) \
            .order_by("-completed_at", "-started_at").limit(5)
        recent_scans = [{
            "id": s.id,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "grade": (s.scorecard or {}).get("grade"),
        } for s in scans]
        if scans:
            needle = host["value"].lower()
            for f in (scans[0].result or {}).get("findings") or []:
                text = f.get("finding") or ""
                if needle in text.lower():
                    related_findings.append({
                        "module": f.get("module"),
                        "finding": text,
                        "risk": f.get("risk"),
                    })
                if len(related_findings) >= 50:
                    break

    return {
        "company_id": company.id,
        "company_name": company.name,
        "host": host,
        "history": history,
        "recent_scans": recent_scans,
        "related_findings": related_findings,
    }


# ── Inventory export (csv|json download) ─────────────────────────────────────
ASSETS_CSV_COLUMNS = [
    "type", "value", "domain", "detail", "ips", "ports",
    "http_status", "risk", "first_seen", "last_seen", "is_new",
]


def _assets_csv_rows(payload: dict) -> list[dict]:
    rows: list[dict] = []
    assets = payload.get("assets", {})

    def _base(atype: str, item: dict) -> dict:
        return {
            "type": atype,
            "value": item.get("value", ""),
            "domain": item.get("domain", ""),
            "detail": "",
            "ips": "",
            "ports": "",
            "http_status": item.get("http_status"),
            "risk": "",
            "first_seen": item.get("first_seen") or "",
            "last_seen": item.get("last_seen") or "",
            "is_new": "true" if item.get("is_new") else "false",
        }

    for item in assets.get("subdomains", []):
        row = _base("subdomain", item)
        row["ips"] = ";".join(item.get("ips") or [])
        rows.append(row)
    for item in assets.get("ips", []):
        row = _base("ip", item)
        row["domain"] = ";".join(item.get("domains") or [])
        row["ips"] = item.get("value", "")
        row["ports"] = ";".join(str(p.get("port")) for p in item.get("open_ports") or [] if p.get("port"))
        rows.append(row)
    for item in assets.get("endpoints", []):
        row = _base("endpoint", item)
        row["detail"] = item.get("source") or ""
        rows.append(row)
    for item in assets.get("technologies", []):
        row = _base("technology", item)
        row["detail"] = item.get("category") or ""
        rows.append(row)
    for item in assets.get("admin_panels", []):
        rows.append(_base("admin_panel", item))
    for item in assets.get("exposed_files", []):
        row = _base("exposed_file", item)
        row["risk"] = item.get("risk") or ""
        rows.append(row)
    for item in assets.get("ports", []):
        row = _base("port", item)
        row["detail"] = item.get("service") or ""
        row["ips"] = item.get("ip") or ""
        row["ports"] = str(item.get("port") or "")
        rows.append(row)
    return rows


@app.get("/api/companies/{company_id}/assets/export")
async def export_company_assets(company_id: int, format: str = Query(default="csv")):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    if format not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="format must be 'csv' or 'json'")
    payload = await _build_company_assets(company)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", company.name).strip("_") or "company"
    if format == "json":
        return Response(
            content=json.dumps(payload, ensure_ascii=False, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}_assets.json"'},
        )
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=ASSETS_CSV_COLUMNS)
    writer.writeheader()
    for row in _assets_csv_rows(payload):
        writer.writerow(row)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_assets.csv"'},
    )


# ── Inventory diff between two arbitrary points ──────────────────────────────
ASSET_TYPE_GROUPS = {
    "subdomain": "subdomains",
    "ip": "ips",
    "endpoint": "endpoints",
    "technology": "technologies",
    "admin_panel": "admin_panels",
    "exposed_file": "exposed_files",
    "port": "ports",
    "app": "apps",
    "neighbor": "neighbors",
}


async def _resolve_scan_point(point: str, domain_ids: list[int]) -> Scan | None:
    """Resolve a scan_id or ISO datetime to the company's nearest completed scan."""
    scan = await Scan.filter(id=point, domain_id__in=domain_ids, status="completed",
                             kind__in=["full", "discover"]).first()
    if scan is not None:
        return scan
    try:
        dt = datetime.fromisoformat(point.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    scans = await Scan.filter(domain_id__in=domain_ids, status="completed",
                              kind__in=["full", "discover"])
    candidates = [s for s in scans if s.completed_at is not None]
    if not candidates:
        return None
    return min(candidates, key=lambda s: abs((s.completed_at - dt).total_seconds()))


@app.get("/api/companies/{company_id}/assets/diff")
async def company_assets_diff(
    company_id: int,
    from_point: str = Query(alias="from"),
    to_point: str = Query(alias="to"),
):
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    domain_ids = [d.id for d in await Domain.filter(company_id=company_id)]
    if not domain_ids:
        raise HTTPException(status_code=409, detail="No domains registered for this company")

    from_scan = await _resolve_scan_point(from_point, domain_ids)
    to_scan = await _resolve_scan_point(to_point, domain_ids)
    if from_scan is None or to_scan is None:
        raise HTTPException(status_code=409, detail="Not enough completed scans to resolve the requested range")
    if not from_scan.completed_at or not to_scan.completed_at or to_scan.completed_at <= from_scan.completed_at:
        raise HTTPException(status_code=409, detail="'to' must resolve to a scan later than 'from'")

    from_at, to_at = from_scan.completed_at, to_scan.completed_at
    assets = await Asset.filter(domain_id__in=domain_ids)
    added: dict[str, list[str]] = {group: [] for group in ASSET_TYPE_GROUPS.values()}
    removed: dict[str, list[str]] = {group: [] for group in ASSET_TYPE_GROUPS.values()}
    for asset in assets:
        group = ASSET_TYPE_GROUPS.get(asset.type)
        if group is None:
            continue
        if asset.first_seen_at and from_at < asset.first_seen_at <= to_at:
            added[group].append(asset.value)
        elif (asset.last_seen_at and from_at < asset.last_seen_at <= to_at
              and asset.first_seen_at and asset.first_seen_at <= from_at):
            removed[group].append(asset.value)
    for group in added:
        added[group].sort()
        removed[group].sort()

    # Modified: metadata changes recorded in AssetHistory within the range.
    # Collapse repeated rows per (asset, field): earliest old -> latest new.
    history = await AssetHistory.filter(
        asset__domain_id__in=domain_ids,
        changed_at__gt=from_at,
        changed_at__lte=to_at,
    ).select_related("asset").order_by("changed_at", "id")
    modified: dict[str, list[dict]] = {group: [] for group in ASSET_TYPE_GROUPS.values()}
    collapsed: dict[tuple[int, str], dict] = {}
    for row in history:
        group = ASSET_TYPE_GROUPS.get(row.asset.type)
        if group is None:
            continue
        old_meta, new_meta = row.old_metadata or {}, row.new_metadata or {}
        for field in sorted((set(old_meta) | set(new_meta)) - {"ports_scanned"}):
            if old_meta.get(field) == new_meta.get(field):
                continue
            key = (row.asset_id, field)
            entry = collapsed.setdefault(key, {
                "value": row.asset.value,
                "field": field,
                "old": old_meta.get(field),
                "new": new_meta.get(field),
                "_group": group,
            })
            entry["new"] = new_meta.get(field)
    for entry in collapsed.values():
        if entry["old"] != entry["new"]:
            group = entry.pop("_group")
            modified[group].append(entry)
    for group in modified:
        modified[group].sort(key=lambda e: (e["value"], e["field"]))

    from_score = (from_scan.scorecard or {}).get("score")
    to_score = (to_scan.scorecard or {}).get("score")
    return {
        "from_scan_at": from_at.isoformat(),
        "to_scan_at": to_at.isoformat(),
        "added": added,
        "removed": removed,
        "modified": modified,
        "score_change": {
            "from_grade": (from_scan.scorecard or {}).get("grade"),
            "to_grade": (to_scan.scorecard or {}).get("grade"),
            "delta": (to_score - from_score) if from_score is not None and to_score is not None else None,
        },
    }


# ── Schedules ──────────────────────────────────────────────────────────────────
def _schedule_response(domain_id: int, schedule: Schedule | None) -> dict:
    if schedule is None:
        return {"domain_id": domain_id, "interval_hours": None, "enabled": False,
                "agent_mode": False, "next_run_at": None,
                "discover_enabled": False, "discover_interval_hours": None,
                "next_discover_at": None}
    return {
        "domain_id": domain_id,
        "interval_hours": schedule.interval_hours,
        "enabled": schedule.enabled,
        "agent_mode": schedule.agent_mode,
        "next_run_at": schedule.next_run_at,
        "discover_enabled": schedule.discover_enabled,
        "discover_interval_hours": schedule.discover_interval_hours,
        "next_discover_at": schedule.next_discover_at,
    }


def _apply_schedule_request(schedule: Schedule, request: ScheduleRequest) -> None:
    """Mutate a Schedule row from a ScheduleRequest (None fields are kept)."""
    now = datetime.now(timezone.utc)
    if request.interval_hours is not None:
        schedule.interval_hours = request.interval_hours
    if request.enabled is not None:
        schedule.enabled = request.enabled
        schedule.next_run_at = now + timedelta(hours=schedule.interval_hours) if request.enabled else None
    elif request.interval_hours is not None and schedule.enabled:
        # Interval changed on an active schedule: restart the countdown.
        schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)
    if request.agent_mode is not None:
        schedule.agent_mode = request.agent_mode
    if request.discover_interval_hours is not None:
        schedule.discover_interval_hours = request.discover_interval_hours
    if request.discover_enabled is not None:
        schedule.discover_enabled = request.discover_enabled
        if request.discover_enabled and schedule.discover_interval_hours:
            schedule.next_discover_at = now + timedelta(hours=schedule.discover_interval_hours)
        elif not request.discover_enabled:
            schedule.next_discover_at = None


@app.put("/api/domains/{domain_id}/schedule", dependencies=[Depends(require_role("operator", "admin"))])
async def upsert_schedule(domain_id: int, request: ScheduleRequest):
    dom = await Domain.get_or_none(id=domain_id)
    if dom is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    schedule = await Schedule.get_or_none(domain_id=domain_id)
    if schedule is None:
        schedule = Schedule(domain_id=domain_id, interval_hours=24, enabled=False)
    _apply_schedule_request(schedule, request)
    await schedule.save()
    return _schedule_response(domain_id, schedule)


@app.get("/api/domains/{domain_id}/schedule")
async def get_schedule(domain_id: int):
    dom = await Domain.get_or_none(id=domain_id)
    if dom is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    schedule = await Schedule.get_or_none(domain_id=domain_id)
    return _schedule_response(domain_id, schedule)


# ── App settings ───────────────────────────────────────────────────────────────
class SettingsUpdateRequest(BaseModel):
    enabled_modules: dict[str, bool] | None = None
    agent_default_steps: int | None = None
    default_interval_hours: int | None = None
    agent_mode_default: bool | None = None
    auto_discover_domains: bool | None = None
    smart_fuzz_enabled: bool | None = None
    smart_fuzz_max_requests: int | None = None
    discovery_enabled: bool | None = None
    vuln_scan_enabled: bool | None = None
    default_discover_interval_hours: int | None = None
    skip_discovery_default: bool | None = None
    chain_eval_enabled: bool | None = None
    chain_eval_max_targets: int | None = None
    chain_eval_fuzz: bool | None = None
    chain_eval_scope: str | None = None
    tools_subfinder: bool | None = None
    tools_httpx: bool | None = None
    tools_katana: bool | None = None
    tools_naabu: bool | None = None
    tools_trufflehog: bool | None = None

    @field_validator("agent_default_steps")
    @classmethod
    def validate_steps(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("agent_default_steps must be >= 1")
        return v

    @field_validator("chain_eval_max_targets")
    @classmethod
    def validate_chain_max(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 50):
            raise ValueError("chain_eval_max_targets must be 1..50")
        return v

    @field_validator("chain_eval_scope")
    @classmethod
    def validate_chain_scope(cls, v: str | None) -> str | None:
        if v is not None and v not in ("new", "all"):
            raise ValueError("chain_eval_scope must be 'new' or 'all'")
        return v

    @field_validator("default_interval_hours")
    @classmethod
    def validate_interval(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("default_interval_hours must be >= 1")
        return v

    @field_validator("default_discover_interval_hours")
    @classmethod
    def validate_discover_interval(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("default_discover_interval_hours must be >= 1")
        return v

    @field_validator("smart_fuzz_max_requests")
    @classmethod
    def validate_fuzz_max(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= SMART_FUZZ_MAX_REQUESTS_CAP):
            raise ValueError(f"smart_fuzz_max_requests must be 1..{SMART_FUZZ_MAX_REQUESTS_CAP}")
        return v


@app.get("/api/settings")
async def get_settings():
    return _settings_payload(await _load_settings())


@app.put("/api/settings", dependencies=[Depends(require_role("admin"))])
async def update_settings(request: SettingsUpdateRequest):
    if request.enabled_modules is not None:
        unknown = sorted(set(request.enabled_modules) - set(SCAN_MODULE_NAMES))
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown module(s): {', '.join(unknown)}")
    updates = {
        "enabled_modules": request.enabled_modules,
        "agent_default_steps": request.agent_default_steps,
        "default_interval_hours": request.default_interval_hours,
        "agent_mode_default": request.agent_mode_default,
        "auto_discover_domains": request.auto_discover_domains,
        "smart_fuzz_enabled": request.smart_fuzz_enabled,
        "smart_fuzz_max_requests": request.smart_fuzz_max_requests,
        "discovery_enabled": request.discovery_enabled,
        "vuln_scan_enabled": request.vuln_scan_enabled,
        "default_discover_interval_hours": request.default_discover_interval_hours,
        "skip_discovery_default": request.skip_discovery_default,
        "chain_eval_enabled": request.chain_eval_enabled,
        "chain_eval_max_targets": request.chain_eval_max_targets,
        "chain_eval_fuzz": request.chain_eval_fuzz,
        "chain_eval_scope": request.chain_eval_scope,
        "tools_subfinder": request.tools_subfinder,
        "tools_httpx": request.tools_httpx,
        "tools_katana": request.tools_katana,
        "tools_naabu": request.tools_naabu,
        "tools_trufflehog": request.tools_trufflehog,
    }
    for key, value in updates.items():
        if value is None:
            continue
        await AppSetting.update_or_create(key=key, defaults={"value": value})
    return _settings_payload(await _load_settings())


# ── Per-domain official app developers ─────────────────────────────────────────
class AppDevelopersRequest(BaseModel):
    app_developers: list[dict]

    @field_validator("app_developers")
    @classmethod
    def validate_developers(cls, v: list[dict]) -> list[dict]:
        out = []
        for item in v:
            if not isinstance(item, dict):
                raise ValueError("each developer must be an object")
            store = item.get("store")
            if store not in ("app_store", "google_play"):
                raise ValueError("store must be 'app_store' or 'google_play'")
            name = str(item.get("name") or "").strip()
            if not name:
                raise ValueError("developer name cannot be empty")
            entry = {"store": store, "name": name}
            if item.get("artist_id"):
                entry["artist_id"] = str(item["artist_id"])
            out.append(entry)
        return out


@app.put("/api/domains/{domain_id}/app-developers")
async def set_app_developers(domain_id: int, request: AppDevelopersRequest, user=Depends(require_role("operator", "admin"))):
    dom = await Domain.get_or_none(id=domain_id)
    if dom is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    dom.app_developers = request.app_developers
    await dom.save()
    return {"domain_id": domain_id, "app_developers": dom.app_developers}


# ── Batch operations (per company) ───────────────────────────────────────────
class BatchScanRequest(BaseModel):
    agent_mode: bool = False


@app.post("/api/companies/{company_id}/scan-all")
async def scan_all_company_domains(company_id: int, request: BatchScanRequest | None = None, user=Depends(require_role("operator", "admin"))):
    """Enqueue a scan for every domain of the company (skips domains already in flight)."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    domains = await Domain.filter(company_id=company_id)
    if not domains:
        raise HTTPException(status_code=400, detail="Company has no domains")
    agent_mode = bool(request and request.agent_mode)
    extra_allowed = [d.domain for d in domains]
    scan_ids: list[str] = []
    skipped = 0
    for d in domains:
        in_flight = any(
            s.get("domain_id") == d.id and s["status"] in ("queued", "running")
            for s in SCANS.values()
        )
        if in_flight:
            skipped += 1
            continue
        scan_id = _create_scan_entry(
            d.domain, d.id, agent_mode=agent_mode,
            extra_allowed=extra_allowed, created_by=user_id_of(user),
        )
        await _insert_queued_scan(scan_id, d.domain, d.id)
        await scan_queue.enqueue(scan_id, d.domain, d.id)
        scan_ids.append(scan_id)
    logger.info(f"Batch scan for company {company_id}: {len(scan_ids)} enqueued, {skipped} skipped (in flight)")
    return {
        "company_id": company_id,
        "enqueued": len(scan_ids),
        "skipped_in_flight": skipped,
        "scan_ids": scan_ids,
        "agent_mode": agent_mode,
    }


@app.post("/api/companies/{company_id}/discover-assets")
async def discover_company_assets(company_id: int, user=Depends(require_role("operator", "admin"))):
    """Lightweight discovery pass (whois/dns/subdomain enum/reverse IP) for every
    domain of the company — populates the asset inventory without a deep scan."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    domains = await Domain.filter(company_id=company_id)
    if not domains:
        raise HTTPException(status_code=400, detail="Company has no domains")
    scan_ids: list[str] = []
    skipped = 0
    for d in domains:
        in_flight = any(
            s.get("domain_id") == d.id and s["status"] in ("queued", "running")
            for s in SCANS.values()
        )
        if in_flight:
            skipped += 1
            continue
        scan_id = _create_scan_entry(d.domain, d.id, created_by=user_id_of(user), kind="discover")
        await _insert_queued_scan(scan_id, d.domain, d.id)
        await scan_queue.enqueue(scan_id, d.domain, d.id)
        scan_ids.append(scan_id)
    logger.info(f"Asset discovery for company {company_id}: {len(scan_ids)} enqueued, {skipped} skipped (in flight)")
    return {
        "company_id": company_id,
        "kind": "discover",
        "enqueued": len(scan_ids),
        "skipped_in_flight": skipped,
        "scan_ids": scan_ids,
    }


@app.post("/api/companies/{company_id}/schedule-all", dependencies=[Depends(require_role("operator", "admin"))])
async def schedule_all_company_domains(company_id: int, request: ScheduleRequest):
    """Apply the same recurrence to every domain of the company. Fields left
    out of the request are preserved per domain (e.g. discovery-only updates
    don't touch the vuln scan schedule)."""
    company = await Company.get_or_none(id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    domains = await Domain.filter(company_id=company_id)
    if not domains:
        raise HTTPException(status_code=400, detail="Company has no domains")
    updated = 0
    for d in domains:
        schedule = await Schedule.get_or_none(domain_id=d.id)
        if schedule is None:
            schedule = Schedule(domain_id=d.id, interval_hours=24, enabled=False)
        _apply_schedule_request(schedule, request)
        await schedule.save()
        updated += 1
    logger.info(f"Batch schedule for company {company_id}: {updated} domains → {request.model_dump(exclude_none=True)}")
    return {
        "company_id": company_id,
        "domains_updated": updated,
        "schedule": request.model_dump(exclude_none=True),
    }


# ── Diffing ────────────────────────────────────────────────────────────────────
@app.get("/api/domains/{domain_id}/diff")
async def domain_diff(domain_id: int):
    dom = await Domain.get_or_none(id=domain_id)
    if dom is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    scans = await Scan.filter(domain_id=domain_id, status="completed",
                              kind__in=["full", "discover"]) \
        .order_by("-completed_at", "-started_at").limit(2)
    if len(scans) < 2:
        raise HTTPException(status_code=409, detail="Need at least 2 completed scans to compute a diff")
    latest, prev = scans[0], scans[1]
    changes = _compute_changes(prev.result, latest.result, prev.id)
    return {
        "domain_id": domain_id,
        "domain": dom.domain,
        "previous_scan_id": prev.id,
        "latest_scan_id": latest.id,
        "changes": changes,
    }


# ── AI Chat Assistant ──────────────────────────────────────────────────────────
def _user_email(user) -> str:
    """Best-effort identity for logs; dev mode hands a dict, real auth a User."""
    if isinstance(user, dict):
        return str(user.get("email") or "unknown")
    return getattr(user, "email", "unknown")


class ChatMessage(BaseModel):
    role: str
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("content must not be empty")
        return v[:4000]


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("message must not be empty")
        return v[:4000]


@app.post("/api/chat")
async def chat(request: ChatRequest, req: Request, user=Depends(require_role("viewer", "operator", "admin"))):
    if not os.getenv("AI_API_KEY"):
        raise HTTPException(status_code=503, detail="AI not configured — set AI_API_KEY")
    client_ip = req.client.host if req.client else "unknown"
    if not _chat_rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 chat messages per minute")
    # Input rail — reject prompt-injection attempts without calling the LLM.
    blocked = chat_guardrails.check_input(request.message)
    if blocked is not None:
        logger.warning("Chat request blocked by input rail (user=%s ip=%s)", _user_email(user), client_ip)
        return {"reply": blocked, "tools_used": [], "blocked": True}
    try:
        result = await chat_assistant.answer(
            request.message,
            history=[m.model_dump() for m in request.history],
        )
    except chat_assistant.AINotConfigured:
        raise HTTPException(status_code=503, detail="AI not configured — set AI_API_KEY")
    except chat_assistant.AIBackendError as e:
        logger.warning("AI backend error in chat: %s", e)
        raise HTTPException(status_code=502, detail="AI backend error")
    # Output rail — redact any secret-looking strings from the LLM reply.
    reply, redacted = chat_guardrails.redact_secrets(result["reply"])
    response: dict[str, Any] = {"reply": reply, "tools_used": result["tools_used"]}
    if redacted:
        logger.info("Chat reply redacted %d secret(s) (user=%s)", redacted, _user_email(user))
        response["redacted_secrets"] = redacted
    return response


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

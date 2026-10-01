# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""Scoring model of Sauron ASM — the single home of the rules that turn scan
results into categories, a 0-100 score and an A-F letter.

Everything a maintainer needs to change scoring is here: category weights,
which module belongs to which category, per-finding reclassification rules,
the score formula, the letter thresholds and the worst-finding caps. See
SCORING.md at the repository root for the model explained end to end.

What is NOT here: each scan module still decides its own `risk` level
(low/medium/high/critical) inside modules/*.py — that is a property of the
check itself. This module only consumes those results.

Pure functions, no FastAPI or database imports, so it can be tested alone.
"""
import math
import re

# ── Grades ─────────────────────────────────────────────────────────────────────
# Letter from the 0-100 score. Order matters (highest first).
GRADE_THRESHOLDS = ((90, "A"), (75, "B"), (60, "C"), (40, "D"))
GRADE_ORDER = "ABCDF"   # best -> worst
# The letter can never look better than the worst finding allows. Checked in
# this order; the first severity with at least one affected module wins.
GRADE_CAPS = (("critical", "D"), ("high", "C"), ("medium", "B"))


def grade_of_score(score: float) -> str:
    for minimum, letter in GRADE_THRESHOLDS:
        if score >= minimum:
            return letter
    return "F"


# ── Score formula constants ────────────────────────────────────────────────────
# Base: each module's risk contributes points, scaled by its category weight,
# averaged over the full module list.
MODULE_RISK_POINTS = {"low": 0, "medium": 25, "high": 60, "critical": 100}
# Penalty: diminishing returns per severity, from category-weighted finding
# counts. Each entry is (max points lost, saturation scale):
#   points = max * (1 - exp(-weighted_count / scale))
FINDING_PENALTY = {"critical": (25, 2), "high": (12, 5), "medium": (4, 12)}

# ── Risk vocabulary ────────────────────────────────────────────────────────────
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: RISK_ORDER.get(r, 0))


# A finding line carries a risk label too. Modules produce the four levels above;
# findings of category `info` carry "info" instead (display and tracking only:
# never a module risk, never counted in the score).
INFO_RISK = "info"
FINDING_RISK_LEVELS = frozenset(RISK_ORDER) | {INFO_RISK}


_LINE_TAG = re.compile(r"^\[(CRITICAL|HIGH|MEDIUM|LOW)\]", re.IGNORECASE)


def line_risk(module_risk: str, finding) -> str:
    """Risk of one finding line. A line that states its own severity
    ("[MEDIUM] Path discovered: ...") keeps it instead of inheriting the
    module's worst one — one /wp-config.php.old in a module must not make every
    other line of that module read as critical. The module's risk stays the
    ceiling, so a tag can lower a line but never raise it."""
    text = finding.get("finding") if isinstance(finding, dict) else finding
    m = _LINE_TAG.match(text) if isinstance(text, str) else None
    if not m or module_risk not in RISK_ORDER:
        return module_risk
    tagged = m.group(1).lower()
    return tagged if RISK_ORDER[tagged] <= RISK_ORDER[module_risk] else module_risk


def finding_risk(module_risk: str, category: str, finding=None) -> str:
    """Risk label of one finding line: its own tag or its module's risk, except
    informational findings, which carry "info" instead of inheriting the
    module's worst risk (otherwise "Email hosted on Google Workspace" would
    read as HIGH)."""
    if category == "info":
        return INFO_RISK
    return line_risk(module_risk, finding) if finding is not None else module_risk


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
    "whois": "info",             # refined per-finding: domain expiration warning is misconfiguration
    "dns": "info",               # refined per-finding: AXFR allowed is a real misconfiguration
    "subdomains": "info",        # enumeration results, incl. sensitive-looking names
    "tech": "info",              # fingerprinting; cookie flags are also reported by cookies
    "waf": "exposure",           # refined per-finding: "WAF detected" is a note, a missing WAF is an exposure
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
    "kev": "vulnerability",          # only version-verified, actively exploited CVEs reach findings
    "wayback": "vulnerability",  # refined per-finding: merely-archived sensitive URLs are exposure
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


def _is_unversioned_tech_disclosure(s: str) -> bool:
    # "Server: cloudflare reveals server technology" is fingerprinting noise;
    # only a disclosed exact version (nginx/1.14.1) is a real hardening gap.
    return "reveals server technology" in s and not re.search(r"\d+\.\d+\.\d+", s)


def _headers_finding_category(finding) -> str:
    return "info" if _is_unversioned_tech_disclosure(str(finding).lower()) else "misconfiguration"


def _subdomain_eval_finding_category(finding) -> str:
    s = str(finding).lower()
    if (s.startswith("chained evaluation:") or "evaluated as" in s
            or "no apim-type candidate" in s or "js bundle exposes" in s
            or _is_unversioned_tech_disclosure(s)):
        return "info"            # summaries / notices / recon notes, not defects
    if "secret" in s:
        return "vulnerability"   # forwarded js_secrets / secret-verification hits
    return "misconfiguration"    # forwarded headers/tech findings from the live host


def _whois_finding_category(finding) -> str:
    # Domain expiration is a real operational/hijack risk (an expired domain
    # can be re-registered by an attacker), not neutral registration inventory.
    return "misconfiguration" if "expires in" in str(finding).lower() else "info"


def _email_finding_category(finding) -> str:
    # Only SPF/DMARC gaps are real email-authentication defects. DKIM absence
    # at well-known selectors is unverifiable (selectors aren't enumerable),
    # provider fingerprinting is inventory, and a failed DNS lookup is
    # inconclusive — none of those may count toward score or grade caps.
    s = str(finding)
    if "inconclusive" in s:
        return "info"
    return "misconfiguration" if ("SPF" in s or "DMARC" in s) else "info"


def _blacklist_finding_category(finding) -> str:
    # A refused DNSBL query is an inconclusive check, not a listing.
    return "info" if "inconclusive" in str(finding) else "vulnerability"


def _wayback_finding_category(finding) -> str:
    s = str(finding)
    if "in archived snapshot of" in s:
        return "vulnerability"   # a secret pattern was actually matched in archived content
    return "exposure"            # a sensitive-looking URL merely appeared in the archive — unconfirmed


def _breach_finding_category(finding) -> str:
    s = str(finding).lower()
    if "skipped" in s or "not configured" in s:
        return "info"            # scanner notes (e.g. "HIBP_API_KEY not configured")
    if "email address(es) discovered" in s:
        return "info"            # crt.sh-style email inventory
    if "hunter.io" in s:
        return "exposure"        # publicly enumerable emails
    return "vulnerability"       # actual breaches / leaked combos / leaked records


def _waf_finding_category(finding) -> str:
    # Only the absence of any WAF/CDN in front of the origin is a finding; a
    # detected WAF is a note about the posture.
    return "exposure" if str(finding).startswith("No WAF") else "info"


def _admin_finding_category(finding) -> str | None:
    """"N path(s) blocked or redirected to login (protected, not exposed)" says
    the opposite of an exposure: it is a note, not something to fix."""
    text = finding.get("finding") if isinstance(finding, dict) else finding
    if isinstance(text, str) and "protected, not exposed" in text:
        return "info"
    return None


FINDING_CATEGORY_RULES = {
    "admin": _admin_finding_category,
    "waf": _waf_finding_category,
    "whois": _whois_finding_category,
    "dns": _dns_finding_category,
    "smart_fuzz": _smart_fuzz_finding_category,
    "secret_verification": _secret_verification_finding_category,
    "api_exposure": _api_exposure_finding_category,
    "mobile_apps": _mobile_apps_finding_category,
    "subdomain_eval": _subdomain_eval_finding_category,
    "breach": _breach_finding_category,
    "wayback": _wayback_finding_category,
    "email": _email_finding_category,
    "headers": _headers_finding_category,
    "blacklist": _blacklist_finding_category,
}

# Unknown modules default to info: an unrecognized module must never tank the
# score by accident.
DEFAULT_FINDING_CATEGORY = "info"


def finding_category(module_name: str, finding) -> str:
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


def _without_dismissed(results: dict, dismissed: dict | None) -> dict:
    """`results` minus the lines a person dismissed (accepted risk or false
    positive). `dismissed` maps module -> indexes into its `findings` list. A
    module that lost lines gets the risk of the lines that remain, so
    dismissing the one critical line of a module lowers the module too."""
    if not dismissed:
        return results
    out = dict(results)
    for name, gone in dismissed.items():
        mod = results.get(name)
        if not gone or not isinstance(mod, dict):
            continue
        kept = [f for i, f in enumerate(mod.get("findings") or []) if i not in gone]
        base = mod.get("risk", "low")
        risks = [line_risk(base, f) for f in kept if finding_category(name, f) != "info"]
        out[name] = {**mod, "findings": kept, "risk": max_risk(*risks) if risks else "low"}
    return out


def overall_score(results: dict, dismissed: dict | None = None) -> dict:
    """Compute a global risk score (0-100) and grade (A-F).

    Category-aware model: findings and module risks are weighted by their
    finding category (vulnerability 100%, misconfiguration 60%, exposure 25%)
    and `info` (neutral inventory: subdomains, the plain list of open ports,
    technologies…) never penalizes. Risky exposed services do count, as
    misconfigurations. A domain with only inventory scores 100/A regardless of
    how large its attack surface is.
    """
    module_names = [
        "whois", "dns", "subdomains", "ports", "ssl", "headers", "email",
        "tech", "breach", "exposed", "blacklist", "cors", "cookies",
        "js_secrets", "secret_verification", "waf", "robots", "dnssec",
        "admin", "tls", "frontend_cve", "cloud_storage", "api_exposure",
        "wayback", "nuclei", "kev", "mobile_apps", "reverse_ip", "subdomain_eval",
        "smart_fuzz",
    ]
    results = _without_dismissed(results, dismissed)
    weights = MODULE_RISK_POINTS
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
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}   # MODULES affected, per severity
    weighted = {"critical": 0.0, "high": 0.0, "medium": 0.0, "low": 0.0}
    by_category = {"vulnerability": 0, "misconfiguration": 0, "exposure": 0, "info": 0}
    for mod_name, mod in results.items():
        if not isinstance(mod, dict):
            continue
        r = mod.get("risk", "low")
        worst = None
        for finding in mod.get("findings") or []:
            cat = finding_category(mod_name, finding)
            by_category[cat] += 1
            lr = line_risk(r, finding)
            if cat == "info" or lr not in counts:
                continue
            weighted[lr] += CATEGORY_SCORE_WEIGHT[cat]
            if worst is None or RISK_ORDER[lr] > RISK_ORDER[worst]:
                worst = lr
        # The displayed count is "modules affected" by their worst scored
        # line: a module with 45 lines is one medium, not 45. The penalty above
        # weighs each line by its own severity.
        if worst is not None:
            counts[worst] += 1

    penalty = sum(
        max_points * (1 - math.exp(-weighted[sev] / scale))
        for sev, (max_points, scale) in FINDING_PENALTY.items()
    )
    score = round(max(0, min(100, base - penalty)))
    grade = grade_of_score(score)
    # The score stays the real 0-100 number (it is what ranks and charts domains);
    # only the LETTER is capped: it can never look better than the worst finding
    # allows (critical -> D, high -> C, medium -> B).
    cap_severity, cap_letter = next(
        ((sev, letter) for sev, letter in GRADE_CAPS if counts[sev] > 0),
        (None, None),
    )
    grade_capped_by = None
    if cap_letter and GRADE_ORDER.index(cap_letter) > GRADE_ORDER.index(grade):
        grade_capped_by = {"severity": cap_severity, "modules": counts[cap_severity],
                           "cap": cap_letter, "score_grade": grade}
        grade = cap_letter
    # Overall risk: only non-info modules can raise it — a large but clean
    # inventory must not read as "high risk".
    scored_risks = [
        r for name, r in zip(module_names, module_risks)
        if MODULE_FINDING_CATEGORY.get(name, DEFAULT_FINDING_CATEGORY) != "info"
    ]
    overall_risk = max_risk(*scored_risks) if scored_risks else "low"
    return {"score": score, "grade": grade, "overall_risk": overall_risk,
            "grade_capped_by": grade_capped_by,
            "findings_by_severity": counts, "findings_by_category": by_category}

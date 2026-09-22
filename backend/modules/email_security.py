"""
Email Security Module
Checks SPF, DKIM, DMARC, MTA-STS records and detects email provider
(Google Workspace / Microsoft 365) via DNS fingerprinting and
Microsoft's public OpenID / GetUserRealm endpoints.
"""
import dns.resolver
import re
import logging
import httpx
from typing import Any

logger = logging.getLogger(__name__)


def _query_txt(domain: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "TXT")
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def _check_spf(domain: str) -> dict:
    records = _query_txt(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]

    result = {
        "exists": bool(spf_records),
        "record": spf_records[0] if spf_records else None,
        "multiple_records": len(spf_records) > 1,
        "policy": None,
        "findings": [],
    }

    if not spf_records:
        result["findings"].append("No SPF record found — email spoofing possible")
        return result

    spf = spf_records[0]

    # Too many lookups (>10 is invalid per RFC 7208)
    lookup_mechanisms = re.findall(r"\b(?:include|a|mx|ptr|exists):", spf)
    if len(lookup_mechanisms) > 10:
        result["findings"].append(f"SPF record exceeds 10 DNS lookup limit ({len(lookup_mechanisms)} found)")

    # Policy
    if "+all" in spf:
        result["policy"] = "+all"
        result["findings"].append("SPF uses '+all' — allows ANY server to send email (critical misconfiguration)")
    elif "~all" in spf:
        result["policy"] = "~all"
        result["findings"].append("SPF uses '~all' (SoftFail) — better to use '-all'")
    elif "-all" in spf:
        result["policy"] = "-all"
    elif "?all" in spf:
        result["policy"] = "?all"
        result["findings"].append("SPF uses '?all' (Neutral) — no protection against spoofing")

    if result["multiple_records"]:
        result["findings"].append("Multiple SPF records found — only one is valid per RFC")

    return result


def _check_dmarc(domain: str) -> dict:
    dmarc_domain = f"_dmarc.{domain}"
    records = _query_txt(dmarc_domain)
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    result = {
        "exists": bool(dmarc_records),
        "record": dmarc_records[0] if dmarc_records else None,
        "policy": None,
        "pct": 100,
        "rua": None,
        "ruf": None,
        "findings": [],
    }

    if not dmarc_records:
        result["findings"].append("No DMARC record found — email authentication not enforced")
        return result

    dmarc = dmarc_records[0]

    # Extract fields
    policy_match = re.search(r"p=(\w+)", dmarc)
    if policy_match:
        result["policy"] = policy_match.group(1)

    pct_match = re.search(r"pct=(\d+)", dmarc)
    if pct_match:
        result["pct"] = int(pct_match.group(1))

    rua_match = re.search(r"rua=([^\s;]+)", dmarc)
    if rua_match:
        result["rua"] = rua_match.group(1)

    ruf_match = re.search(r"ruf=([^\s;]+)", dmarc)
    if ruf_match:
        result["ruf"] = ruf_match.group(1)

    if result["policy"] == "none":
        result["findings"].append("DMARC policy is 'none' — monitoring only, no enforcement")
    elif result["policy"] == "quarantine":
        result["findings"].append("DMARC policy is 'quarantine' — consider upgrading to 'reject'")

    if result["pct"] < 100:
        result["findings"].append(f"DMARC only applies to {result['pct']}% of messages")

    if not result["rua"]:
        result["findings"].append("No DMARC aggregate report address (rua) configured")

    return result


def _check_dkim(domain: str) -> dict:
    """Check for common DKIM selectors.

    DKIM selectors are NOT enumerable via DNS — absence here only means no
    record at the well-known selectors, never that DKIM is missing. The
    finding is therefore informational, not a defect.
    """
    common_selectors = [
        # Generic
        "default", "mail", "email", "dkim", "smtp", "mx", "k1",
        # Google Workspace
        "google",
        # Microsoft 365
        "selector1", "selector2",
        # SendGrid
        "s1", "s2",
        # Mailchimp
        "k2", "k3",
        # Mailgun
        "mg", "mailo", "mailgun",
        # ProtonMail
        "protonmail", "protonmail2", "protonmail3",
        # Fastmail
        "fm1", "fm2", "fm3",
        # Zendesk / HubSpot / Campaign Monitor / Mandrill
        "zendesk1", "zendesk2", "hs1", "hs2", "hubspot", "cm", "mandrill",
    ]
    found_selectors = []
    for selector in common_selectors:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            records = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for r in records:
                txt = str(r).strip('"')
                # "p=" with an empty value is a REVOKED key — not evidence of DKIM
                if "v=DKIM1" in txt or (("p=" in txt) and not txt.rstrip().endswith("p=")):
                    found_selectors.append({"selector": selector, "record": txt[:100]})
        except Exception:
            pass

    return {
        "exists": bool(found_selectors),
        "selectors_found": found_selectors,
        "selectors_checked": len(common_selectors),
        "findings": [] if found_selectors else [
            f"DKIM not detectable via {len(common_selectors)} common selectors — "
            "may still be configured with a custom selector (not enumerable via DNS)"
        ],
    }


def _check_mta_sts(domain: str) -> dict:
    records = _query_txt(f"_mta-sts.{domain}")
    sts_records = [r for r in records if "v=STSv1" in r]
    return {
        "exists": bool(sts_records),
        "record": sts_records[0] if sts_records else None,
    }


def _check_bimi(domain: str) -> dict:
    records = _query_txt(f"default._bimi.{domain}")
    bimi_records = [r for r in records if "v=BIMI1" in r]
    return {
        "exists": bool(bimi_records),
        "record": bimi_records[0] if bimi_records else None,
    }


# ─── Email provider detection ─────────────────────────────────────────────────

_GOOGLE_MX_PATTERNS = [
    "google.com", "googlemail.com", "aspmx.l.google.com",
    "alt1.aspmx", "alt2.aspmx", "smtp.google.com",
]
_MS_MX_PATTERNS = [
    "mail.protection.outlook.com", "outlook.com",
]
_GOOGLE_SPF_INCLUDES = ["_spf.google.com", "google.com/a/"]
_MS_SPF_INCLUDES    = ["spf.protection.outlook.com", "protection.outlook.com"]


def _mx_records(domain: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".").lower() for r in answers]
    except Exception:
        return []


def _detect_provider(domain: str, spf_record: str | None) -> dict:
    """
    Detect whether the domain uses Google Workspace or Microsoft 365.

    Technique 1 — MX record fingerprinting (passive DNS).
    Technique 2 — SPF include fingerprinting (passive DNS).
    Technique 3 — Microsoft OpenID tenant endpoint (unauthenticated HTTP):
        GET https://login.microsoftonline.com/{domain}/.well-known/openid-configuration
        Returns 200 + JSON with tenant_id if the domain has an Azure AD / M365 tenant.
    Technique 4 — Microsoft GetUserRealm (unauthenticated, per RFC-like MSFT API):
        Tells whether a given UPN exists in M365 (Managed/Federated/Unknown).
        Used by o365spray, AADInternals, theHarvester.
    """
    result: dict = {
        "provider": "unknown",          # google | microsoft | self-hosted | unknown
        "google_workspace": False,
        "microsoft_365": False,
        "mx_records": [],
        "tenant_id": None,              # M365 tenant GUID if detected
        "tenant_name": None,            # e.g. contoso.onmicrosoft.com
        "detection_method": [],
        "findings": [],
    }

    # ── Technique 1: MX fingerprinting ───────────────────────────────────────
    mxs = _mx_records(domain)
    result["mx_records"] = mxs

    for mx in mxs:
        if any(p in mx for p in _GOOGLE_MX_PATTERNS):
            result["google_workspace"] = True
            result["provider"] = "google"
            result["detection_method"].append("mx_record")
            break
        if any(p in mx for p in _MS_MX_PATTERNS):
            result["microsoft_365"] = True
            result["provider"] = "microsoft"
            result["detection_method"].append("mx_record")
            break

    # ── Technique 2: SPF include fingerprinting ───────────────────────────────
    if spf_record:
        spf_lower = spf_record.lower()
        if any(inc in spf_lower for inc in _GOOGLE_SPF_INCLUDES):
            result["google_workspace"] = True
            result["provider"] = "google"
            if "spf_include" not in result["detection_method"]:
                result["detection_method"].append("spf_include")
        if any(inc in spf_lower for inc in _MS_SPF_INCLUDES):
            result["microsoft_365"] = True
            result["provider"] = "microsoft"
            if "spf_include" not in result["detection_method"]:
                result["detection_method"].append("spf_include")

    # ── Technique 3: Microsoft OpenID tenant endpoint ─────────────────────────
    # Always probe M365 regardless of MX/SPF (some orgs route mail elsewhere
    # but still have Azure AD / hybrid identities in M365)
    try:
        r = httpx.get(
            f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
            timeout=5, follow_redirects=True,
        )
        if r.status_code == 200:
            data = r.json()
            token_ep = data.get("token_endpoint", "")
            # token_endpoint contains the tenant GUID:
            # https://login.microsoftonline.com/{tenant_id}/oauth2/token
            tid_match = re.search(
                r"login\.microsoftonline\.com/([0-9a-f-]{36})",
                token_ep, re.I
            )
            issuer = data.get("issuer", "")
            # issuer: https://sts.windows.net/{tenant_id}/
            if not tid_match:
                tid_match = re.search(r"([0-9a-f-]{36})", issuer)

            tenant_region = data.get("tenant_region_scope")  # e.g. "WW"
            cloud_instance = data.get("cloud_instance_name")  # e.g. "microsoftonline.com"

            # Exclude the common "organizations" / "common" pseudo-tenants
            if tid_match:
                tid = tid_match.group(1)
                PSEUDO = {"9188040d-6c67-4c5b-b112-36a304b66dad",
                          "f8cdef31-a31e-4b4a-93e4-5f571e91255a"}
                if tid not in PSEUDO:
                    result["microsoft_365"] = True
                    result["provider"] = "microsoft"
                    result["tenant_id"] = tid
                    result["tenant_region"] = tenant_region
                    result["cloud_instance"] = cloud_instance
                    if "openid_tenant" not in result["detection_method"]:
                        result["detection_method"].append("openid_tenant")
                    result["findings"].append(
                        f"Microsoft 365 tenant confirmed (tenant_id: {tid})"
                    )
    except Exception as e:
        logger.debug(f"[email] M365 OpenID probe failed for {domain}: {e}")

    # ── Technique 4: GetUserRealm — domain-level check ────────────────────────
    # Probes a sentinel address admin@{domain} to get realm info without
    # enumerating real accounts (same technique used by AADInternals / o365spray)
    if result["microsoft_365"]:
        try:
            r = httpx.get(
                "https://login.microsoftonline.com/GetUserRealm.srf",
                params={"login": f"admin@{domain}", "xml": "1"},
                timeout=5,
            )
            if r.status_code == 200:
                ns_type = re.search(r"<NameSpaceType>([^<]+)</NameSpaceType>", r.text)
                auth_url = re.search(r"<AuthURL>([^<]+)</AuthURL>", r.text)
                cloud_inst = re.search(r"<CloudInstanceName>([^<]+)</CloudInstanceName>", r.text)
                domain_name = re.search(r"<DomainName>([^<]+)</DomainName>", r.text)

                if ns_type:
                    nst = ns_type.group(1).strip()
                    result["realm_type"] = nst  # Managed | Federated | Unknown
                    if nst == "Managed":
                        result["findings"].append(
                            "M365 realm: Managed (native Azure AD authentication)"
                        )
                    elif nst == "Federated":
                        fed_url = auth_url.group(1) if auth_url else None
                        result["federation_url"] = fed_url
                        result["findings"].append(
                            f"M365 realm: Federated — IdP: {fed_url or 'unknown'}"
                        )
                if cloud_inst:
                    result["cloud_instance"] = cloud_inst.group(1).strip()
                if domain_name:
                    result["tenant_name"] = domain_name.group(1).strip()
                if "getuserrealm" not in result["detection_method"]:
                    result["detection_method"].append("getuserrealm")
        except Exception as e:
            logger.debug(f"[email] GetUserRealm failed for {domain}: {e}")

    # Summary finding
    if result["google_workspace"]:
        result["findings"].insert(0, "Email hosted on Google Workspace")
    elif result["microsoft_365"]:
        result["findings"].insert(0, "Email hosted on Microsoft 365")
    elif mxs:
        result["provider"] = "self-hosted"
        result["findings"].insert(0, f"Self-hosted / third-party email (MX: {mxs[0]})")

    return result


def run(domain: str) -> dict[str, Any]:
    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain)
    mta_sts = _check_mta_sts(domain)
    bimi = _check_bimi(domain)
    provider = _detect_provider(domain, spf.get("record"))

    all_findings = spf["findings"] + dmarc["findings"] + dkim["findings"] + provider["findings"]

    # Risk assessment
    risk = "low"
    if not spf["exists"] and not dmarc["exists"]:
        risk = "critical"
    elif not dmarc["exists"] or dmarc["policy"] == "none":
        risk = "high"
    elif not spf["exists"] or dmarc["policy"] == "quarantine":
        risk = "medium"
    elif spf.get("policy") in ("~all", "?all", "+all"):
        risk = "medium"

    return {
        "status": "ok",
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "mta_sts": mta_sts,
        "bimi": bimi,
        "provider": provider,
        "risk": risk,
        "findings": all_findings,
    }

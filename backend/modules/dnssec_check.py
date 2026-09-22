"""
DNSSEC Validation Module
Checks DNSSEC signing, DS records, and NSEC/NSEC3 presence
"""
import dns.resolver
import dns.rdatatype
import dns.dnssec
import dns.query
import dns.message
import dns.name
import logging
from typing import Any

logger = logging.getLogger(__name__)

TIMEOUT = 5


def _query(domain: str, rtype: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except Exception:
        return []


def _query_with_do_bit(domain: str) -> dict:
    """Query with DNSSEC OK bit set to check if server supports DNSSEC."""
    try:
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        nameservers = dns.resolver.Resolver().nameservers
        for ns in nameservers[:2]:
            try:
                response = dns.query.udp(request, ns, timeout=TIMEOUT)
                has_ad = bool(response.flags & dns.flags.AD)
                has_dnskey = any(r.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer for r in rrset)
                has_rrsig = any(r.rdtype == dns.rdatatype.RRSIG for rrset in response.answer for r in rrset)
                return {
                    "ad_flag": has_ad,
                    "dnskey_present": has_dnskey,
                    "rrsig_present": has_rrsig,
                    "success": True,
                }
            except Exception:
                continue
    except Exception:
        pass
    return {"ad_flag": False, "dnskey_present": False, "rrsig_present": False, "success": False}


def run(domain: str) -> dict[str, Any]:
    findings: list[str] = []
    risk = "low"

    # Check DNSKEY records (zone signing keys)
    dnskey_records = _query(domain, "DNSKEY")
    has_dnskey = bool(dnskey_records)

    # Check DS records (delegation signer, in parent zone)
    # DS records live in the parent domain, query there
    parts = domain.split(".")
    parent = ".".join(parts[-2:]) if len(parts) > 2 else domain
    try:
        ds_records_raw = _query(domain, "DS")
        ds_records = ds_records_raw
    except Exception:
        ds_records = []

    has_ds = bool(ds_records)

    # Check RRSIG (signature over records)
    rrsig_records = _query(domain, "RRSIG")
    has_rrsig = bool(rrsig_records)

    # Check NSEC / NSEC3 (authenticated denial of existence)
    nsec_records = _query(domain, "NSEC")
    nsec3_records = _query(domain, "NSEC3")
    has_nsec = bool(nsec_records)
    has_nsec3 = bool(nsec3_records)

    # DO-bit query
    do_result = _query_with_do_bit(domain)

    # Determine DNSSEC state
    signed = has_dnskey or has_rrsig or do_result.get("dnskey_present", False)
    validated = do_result.get("ad_flag", False)

    if not signed:
        # Most of the internet does not deploy DNSSEC — treat as an
        # informational hardening note, not a vulnerability.
        findings.append("DNSSEC not configured (optional hardening, low adoption) — zone is unsigned")
        risk = "low"
    elif signed and not validated:
        findings.append("DNSSEC records present but AD (Authenticated Data) flag not set by resolver — validation may not be enforced")
        risk = "low"
    else:
        pass  # fully signed and validated

    if has_nsec and not has_nsec3:
        findings.append("NSEC used instead of NSEC3 — zone walking possible (enumerate all DNS records)")
        risk = max(risk, "medium", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r, 0))

    return {
        "status": "ok",
        "signed": signed,
        "validated": validated,
        "has_dnskey": has_dnskey,
        "has_ds": has_ds,
        "has_rrsig": has_rrsig,
        "has_nsec": has_nsec,
        "has_nsec3": has_nsec3,
        "dnskey_count": len(dnskey_records),
        "ds_records": ds_records[:5],
        "ad_flag": do_result.get("ad_flag", False),
        "risk": risk,
        "findings": findings,
    }

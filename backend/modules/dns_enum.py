"""
DNS Enumeration Module
Queries all common DNS record types
"""
import dns.resolver
import dns.reversename
import logging
from typing import Any

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR", "SRV"]


def _query(domain: str, rtype: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []
    except Exception as e:
        logger.debug(f"[dns] {rtype} {domain}: {e}")
        return []


def run(domain: str) -> dict[str, Any]:
    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        results = _query(domain, rtype)
        if results:
            records[rtype] = results

    # Detect zone transfer vulnerability
    zone_transfer_vuln = False
    ns_records = records.get("NS", [])
    for ns in ns_records:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns.rstrip("."), domain, timeout=5))
            if z:
                zone_transfer_vuln = True
                break
        except Exception:
            pass

    # Risk assessment
    risk = "low"
    findings = []

    if zone_transfer_vuln:
        risk = "critical"
        findings.append("Zone transfer (AXFR) is allowed — exposes full DNS zone")

    txt = " ".join(records.get("TXT", []))
    if "v=spf1" not in txt.lower():
        findings.append("No SPF record found in TXT")
        risk = max_risk(risk, "medium")

    return {
        "status": "ok",
        "records": records,
        "zone_transfer_vulnerable": zone_transfer_vuln,
        "risk": risk,
        "findings": findings,
    }


def max_risk(current: str, new: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current

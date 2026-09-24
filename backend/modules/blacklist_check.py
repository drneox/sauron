"""
IP Reputation & Blacklist Check Module
Checks if domain IPs appear in public DNS-based blocklists (DNSBLs)
and queries free threat intelligence APIs.
"""
import socket
import asyncio
import httpx
import dns.resolver
import logging
from typing import Any

logger = logging.getLogger(__name__)

# DNS-based blocklists (DNSBLs) — all free, no API key
DNSBL_LISTS = [
    ("zen.spamhaus.org", "Spamhaus ZEN (spam + exploits)"),
    ("b.barracudacentral.org", "Barracuda Reputation"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("spam.dnsbl.sorbs.net", "SORBS Spam"),
    ("http.dnsbl.sorbs.net", "SORBS HTTP Proxy"),
    ("socks.dnsbl.sorbs.net", "SORBS SOCKS Proxy"),
    ("dul.dnsbl.sorbs.net", "SORBS DUL (dynamic IP)"),
    ("ix.dnsbl.manitu.net", "Manitu"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT Level 1"),
    ("dnsbl-2.uceprotect.net", "UCEPROTECT Level 2"),
    ("cbl.abuseat.org", "CBL (bot/malware infected)"),
    ("xbl.spamhaus.org", "Spamhaus XBL (exploits)"),
    ("pbl.spamhaus.org", "Spamhaus PBL (policy)"),
    ("truncate.gbudb.net", "GBUdb (spam)"),
    ("dnsbl.dronebl.org", "DroneBL (network abuse)"),
    ("db.wpbl.info", "WPBL"),
    ("rbl.interserver.net", "Interserver RBL"),
    ("korea.services.net", "Korean IP Block"),
    ("blackholes.mail-abuse.org", "Mail Abuse (MAPS)"),
]

# URL/domain reputation lists
DOMAIN_LISTS = [
    ("dbl.spamhaus.org", "Spamhaus Domain Block List"),
    ("0spam.fusionzero.com", "0spam"),
    ("multi.surbl.org", "SURBL Multi"),
    ("combined.abuse.ch", "abuse.ch combined"),
]


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address: 1.2.3.4 → 4.3.2.1"""
    return ".".join(reversed(ip.split(".")))


def _is_refusal(code: str) -> bool:
    """127.255.255.x are DNSBL *error* answers, never listings.

    Spamhaus replies 127.255.255.254 to any query arriving through a public /
    open resolver (even for 8.8.8.8) and 127.255.255.255 on excessive volume.
    """
    return code.startswith("127.255.255.")


def _check_dnsbl(ip: str, dnsbl: str, label: str) -> dict | None:
    """Check a single DNSBL. Returns dict if listed, None if clean."""
    reversed_ip = _reverse_ip(ip)
    query = f"{reversed_ip}.{dnsbl}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(query, "A")
        codes = [str(a) for a in answers]
        if codes and all(_is_refusal(c) for c in codes):
            return {"list": label, "dnsbl": dnsbl, "codes": codes, "refused": True}
        codes = [c for c in codes if not _is_refusal(c)]

        # Decode Spamhaus return codes
        details = None
        if "spamhaus" in dnsbl.lower():
            code_map = {
                "127.0.0.2": "SBL — direct spam source",
                "127.0.0.3": "SBL CSS — spam support service",
                "127.0.0.4": "XBL — CBL (malware/bot)",
                "127.0.0.5": "XBL — NJABL",
                "127.0.0.10": "PBL — ISP maintained",
                "127.0.0.11": "PBL — Spamhaus maintained",
            }
            for code in codes:
                if code in code_map:
                    details = code_map[code]
                    break

        return {
            "list": label,
            "dnsbl": dnsbl,
            "codes": codes,
            "details": details,
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception as e:
        logger.debug(f"[blacklist] {query}: {e}")
        return None


def _check_domain_dnsbl(domain: str, dnsbl: str, label: str) -> dict | None:
    """Check a domain against a domain blocklist."""
    query = f"{domain}.{dnsbl}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(query, "A")
        codes = [str(a) for a in answers]
        if codes and all(_is_refusal(c) for c in codes):
            return {"list": label, "dnsbl": dnsbl, "codes": codes, "refused": True}
        return {
            "list": label,
            "dnsbl": dnsbl,
            "codes": [c for c in codes if not _is_refusal(c)],
            "details": None,
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None


def _check_urlhaus(domain: str) -> dict:
    """Check URLhaus (abuse.ch) for malware URLs on this domain."""
    result = {"found": False, "urls": [], "checked": False}
    try:
        resp = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            headers={"User-Agent": "Dumb-Auditor/1.0"},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["checked"] = True
            if data.get("query_status") == "is_host":
                urls = data.get("urls", [])
                result["found"] = True
                result["url_count"] = len(urls)
                result["urls"] = [
                    {
                        "url": u.get("url", "")[:80],
                        "threat": u.get("threat"),
                        "date_added": u.get("date_added"),
                        "tags": u.get("tags", []),
                    }
                    for u in urls[:5]
                ]
            # else: not_found is clean
    except Exception as e:
        logger.debug(f"[blacklist/urlhaus] {domain}: {e}")
    return result


def _check_threatfox(domain: str) -> dict:
    """Check ThreatFox (abuse.ch) IOC database."""
    result = {"found": False, "iocs": [], "checked": False}
    try:
        resp = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": domain},
            headers={"User-Agent": "Dumb-Auditor/1.0"},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["checked"] = True
            if data.get("query_status") == "ok":
                iocs = data.get("data", [])
                result["found"] = bool(iocs)
                result["ioc_count"] = len(iocs)
                result["iocs"] = [
                    {
                        "ioc": i.get("ioc"),
                        "threat_type": i.get("threat_type"),
                        "malware": i.get("malware"),
                        "confidence": i.get("confidence_level"),
                        "first_seen": i.get("first_seen"),
                    }
                    for i in iocs[:3]
                ]
    except Exception as e:
        logger.debug(f"[blacklist/threatfox] {domain}: {e}")
    return result


def run(domain: str) -> dict[str, Any]:
    # Resolve domain to IP(s)
    ips = []
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if ":" not in ip and ip not in ips:  # IPv4 only for DNSBLs
                ips.append(ip)
    except socket.gaierror as e:
        return {"status": "error", "error": str(e), "listed_on": [], "risk": "low", "findings": []}

    if not ips:
        return {"status": "error", "error": "Could not resolve IP", "listed_on": [], "risk": "low", "findings": []}

    primary_ip = ips[0]

    # Check DNSBLs concurrently using threads
    import concurrent.futures
    listed_on = []
    refused: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        # IP-based checks
        ip_futures = {
            executor.submit(_check_dnsbl, primary_ip, dnsbl, label): (primary_ip, dnsbl)
            for dnsbl, label in DNSBL_LISTS
        }
        # Domain-based checks
        domain_futures = {
            executor.submit(_check_domain_dnsbl, domain, dnsbl, label): (domain, dnsbl)
            for dnsbl, label in DOMAIN_LISTS
        }

        for future in concurrent.futures.as_completed({**ip_futures, **domain_futures}):
            result = future.result()
            if result and result.get("refused"):
                refused.append(result["list"])
            elif result:
                listed_on.append(result)

    # Threat intelligence checks
    urlhaus = _check_urlhaus(domain)
    threatfox = _check_threatfox(domain)

    # Risk assessment
    risk = "low"
    findings = []

    if listed_on:
        risk = "critical" if len(listed_on) >= 3 else "high"
        for entry in listed_on:
            detail = f" ({entry['details']})" if entry.get("details") else ""
            findings.append(f"IP {primary_ip} listed on {entry['list']}{detail}")

    if refused:
        findings.append(
            f"Blocklist check inconclusive: {len(refused)} list(s) refused the query "
            "(public or rate-limited DNS resolver) — results are a lower bound"
        )

    if urlhaus.get("found"):
        risk = "critical"
        findings.append(
            f"Domain found in URLhaus malware database — {urlhaus.get('url_count', 0)} malicious URLs"
        )

    if threatfox.get("found"):
        risk = "critical"
        for ioc in threatfox.get("iocs", []):
            findings.append(
                f"ThreatFox IOC: {ioc.get('threat_type')} — {ioc.get('malware')} "
                f"(confidence: {ioc.get('confidence')}%)"
            )

    # Build reputation summary
    spamhaus_listed = any("spamhaus" in e["dnsbl"].lower() for e in listed_on)
    barracuda_listed = any("barracuda" in e["dnsbl"].lower() for e in listed_on)

    return {
        "status": "ok",
        "ip": primary_ip,
        "all_ips": ips,
        "dnsbl_count": len(DNSBL_LISTS) + len(DOMAIN_LISTS),
        "listed_on": listed_on,
        "listing_count": len(listed_on),
        "refused_lists": refused,
        "clean": len(listed_on) == 0,
        "spamhaus_listed": spamhaus_listed,
        "barracuda_listed": barracuda_listed,
        "urlhaus": urlhaus,
        "threatfox": threatfox,
        "risk": risk,
        "findings": findings,
    }

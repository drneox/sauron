"""
Reverse IP Lookup Module
Resolves the apex domain's IPs and performs a reverse IP lookup
(api.hackertarget.com) to find co-hosted domains. IPs belonging to known
CDN networks are skipped (shared CDN edge, no meaningful neighbors).
Co-hosted domains containing the brand are attributed to the company;
the rest are reported as neighbors (indirect attack surface).
"""
import ipaddress
import logging
import socket
from typing import Any

import httpx
import tldextract

logger = logging.getLogger(__name__)

REVERSE_LOOKUP_URL = "https://api.hackertarget.com/reverseiplookup/"
MAX_IPS = 3
MAX_DOMAINS_PER_IP = 100

# Well-known CDN / edge provider IPv4 ranges. Reverse lookups against these
# are meaningless (shared anycast edge), so they are skipped.
CDN_NETWORKS: list[tuple[str, ipaddress.IPv4Network]] = [
    (name, ipaddress.ip_network(cidr))
    for name, cidrs in {
        "Cloudflare": [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ],
        "Akamai": [
            "23.0.0.0/12", "23.32.0.0/11", "23.192.0.0/11",
            "104.64.0.0/10", "184.24.0.0/13", "2.16.0.0/13",
            "95.100.0.0/15",
        ],
        "Fastly": ["151.101.0.0/16"],
        "Google": [
            "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
            "172.253.0.0/16",
        ],
        "AWS CloudFront": [
            "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
            "52.84.0.0/15", "52.124.128.0/17", "54.182.0.0/16",
            "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18",
            "54.239.192.0/19", "64.252.64.0/18", "70.132.0.0/18",
            "71.152.0.0/17", "99.84.0.0/16", "143.204.0.0/16",
            "204.246.160.0/19", "205.251.192.0/19", "216.137.32.0/19",
        ],
    }.items()
    for cidr in cidrs
]


def _cdn_name(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, network in CDN_NETWORKS:
        if addr in network:
            return name
    return None


def _resolve_ips(domain: str) -> list[str]:
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    if not ips:
        try:
            ips.append(socket.gethostbyname(domain))
        except socket.gaierror:
            pass
    return ips[:MAX_IPS]


def _reverse_lookup(ip: str) -> tuple[list[str], str | None]:
    """Returns (domains, note). note is set on rate limit or API-side error."""
    try:
        resp = httpx.get(REVERSE_LOOKUP_URL, params={"q": ip}, timeout=10)
    except Exception as e:
        return [], f"lookup failed: {e}"
    text = resp.text.strip()
    if resp.status_code != 200:
        return [], f"HTTP {resp.status_code}"
    lowered = text.lower()
    if "api count exceeded" in lowered or "error check" in lowered:
        return [], "rate limited"
    if "no dns" in lowered or lowered.startswith("error"):
        return [], text[:80]
    domains = []
    for line in text.splitlines():
        host = line.strip().lower()
        if host and "." in host and " " not in host:
            domains.append(host)
        if len(domains) >= MAX_DOMAINS_PER_IP:
            break
    return domains, None


def run(domain: str) -> dict[str, Any]:
    brand = tldextract.extract(domain).domain or domain
    apex = tldextract.extract(domain).registered_domain or domain
    result: dict[str, Any] = {
        "status": "ok",
        "ips_checked": [],
        "attributed": [],
        "neighbors": [],
        "shared_hosting_risk": False,
        "risk": "low",
        "findings": [],
    }

    ips = _resolve_ips(domain)
    if not ips:
        result["status"] = "error"
        result["error"] = f"Could not resolve any A record for {domain}"
        return result

    seen_hosts = {domain}
    for ip in ips:
        cdn = _cdn_name(ip)
        if cdn:
            result["ips_checked"].append({"ip": ip, "cdn": cdn, "skipped": True})
            result["findings"].append(
                f"IP {ip} belongs to {cdn} (shared CDN) — reverse lookup skipped"
            )
            continue

        hosts, note = _reverse_lookup(ip)
        result["ips_checked"].append({"ip": ip, "cdn": None, "skipped": False, "note": note})
        if note:
            result["findings"].append(f"Reverse lookup for {ip} incomplete: {note}")
            continue

        for host in hosts:
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            # Subdomains of the scanned apex are in-scope assets, not neighbors
            if host == apex or host.endswith("." + apex):
                result["attributed"].append({"domain": host, "ip": ip, "kind": "subdomain"})
            elif brand.lower() in host:
                result["attributed"].append({"domain": host, "ip": ip, "kind": "brand"})
            else:
                result["neighbors"].append({"domain": host, "ip": ip, "neighbor_of": domain})

    subdomain_hits = [a for a in result["attributed"] if a.get("kind") == "subdomain"]
    if subdomain_hits:
        result["findings"].append(
            f"{len(subdomain_hits)} additional subdomain(s) discovered via reverse IP "
            f"(e.g. {', '.join(a['domain'] for a in subdomain_hits[:3])})"
        )

    if result["neighbors"]:
        result["shared_hosting_risk"] = True
        result["risk"] = "medium"
        sample = ", ".join(n["domain"] for n in result["neighbors"][:3])
        result["findings"].append(
            f"{len(result['neighbors'])} unrelated domain(s) co-hosted on the same IP as "
            f"{domain} (e.g. {sample}) — shared hosting exposes the brand to neighbor compromise"
        )

    return result

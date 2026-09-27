"""
ip_lookup.py — what is behind an IP that appears in the inventory.

Backs SauronBot's `ip_lookup` tool. Answers the question "is this IP really
shared, or is it vendor edge infrastructure?" with three independent facts:

  owner    ASN / network name (Team Cymru DNS) and reverse DNS
  probe    how the IP answers for a hostname that cannot exist there, and which
           platform headers it sends (a CDN / front-door edge answers any name
           with its own generic response; a VM answers with its default site)
  ports    which common ports accept a connection

Only IPs that are already in the inventory are probed, so the tool cannot be
used as a generic scanner.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename
import httpx

DNS_TIMEOUT = 4
PROBE_TIMEOUT = 6
PROBE_PORTS = (22, 80, 443, 3389, 8080, 8443)

# Headers that only a platform edge / CDN adds, whatever site sits behind it.
PLATFORM_HEADERS = {
    "x-azure-ref": "Azure Front Door / Azure CDN",
    "x-msedge-ref": "Microsoft edge",
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-served-by": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-vercel-id": "Vercel",
    "x-nf-request-id": "Netlify",
}


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def parse_cymru_origin(txt: str) -> dict[str, str] | None:
    """'8075 | 150.171.0.0/16 | US | arin | 2015-11-24' → {asn, prefix, country, registry}."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 4 or not parts[0]:
        return None
    asn = parts[0].split()[0]
    return {"asn": asn, "prefix": parts[1], "country": parts[2], "registry": parts[3]}


def parse_cymru_asn_name(txt: str) -> str | None:
    """'8075 | US | arin | 1997-03-31 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft…' → the name."""
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return parts[4] if len(parts) >= 5 and parts[4] else None


def platform_signals(headers: dict[str, str]) -> list[str]:
    """Platforms whose marker headers are present."""
    lowered = {k.lower() for k in headers}
    found: list[str] = []
    for header, platform in PLATFORM_HEADERS.items():
        if header in lowered and platform not in found:
            found.append(platform)
    return found


def _txt(name: str) -> str | None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        return str(resolver.resolve(name, "TXT")[0])
    except (dns.exception.DNSException, IndexError):
        return None


def owner_of(ip: str) -> dict[str, Any]:
    """ASN, prefix, network name and reverse DNS. Fields are None when unavailable."""
    out: dict[str, Any] = {"asn": None, "prefix": None, "name": None, "country": None, "reverse_dns": None}
    if ipaddress.ip_address(ip).version == 4:
        origin = _txt(".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com")
        info = parse_cymru_origin(origin) if origin else None
        if info:
            out.update(asn=f"AS{info['asn']}", prefix=info["prefix"], country=info["country"])
            name = _txt(f"AS{info['asn']}.asn.cymru.com")
            out["name"] = parse_cymru_asn_name(name) if name else None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        ptr = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        out["reverse_dns"] = str(ptr[0]).rstrip(".")
    except dns.exception.DNSException:
        pass
    return out


def open_ports(ip: str) -> list[int]:
    found = []
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=2):
                found.append(port)
        except OSError:
            continue
    return found


def probe_unknown_host(ip: str) -> dict[str, Any]:
    """GET / over HTTPS asking the IP for a name that cannot exist there."""
    invented = f"sauron-probe-{uuid.uuid4().hex[:10]}.invalid"
    result: dict[str, Any] = {"host_asked": invented, "reachable": False}
    try:
        with httpx.Client(verify=False, timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
            resp = client.get(
                f"https://{ip}/",
                headers={"Host": invented, "User-Agent": "Sauron-ASM"},
                extensions={"sni_hostname": invented},
            )
        headers = dict(resp.headers)
        result.update(
            reachable=True,
            status=resp.status_code,
            server=headers.get("server"),
            platform_headers=platform_signals(headers),
            body_bytes=len(resp.content),
            title=(re.search(r"<title[^>]*>(.*?)</title>", resp.text[:20000], re.I | re.S) or [None, None])[1],
        )
    except Exception as exc:
        result["error"] = type(exc).__name__
    return result


def verdict_hint(owner: dict[str, Any], probe: dict[str, Any], ports: list[int], company_count: int) -> str:
    """A cautious reading of the facts, for the assistant to explain."""
    platforms = probe.get("platform_headers") or []
    only_web = bool(ports) and set(ports) <= {80, 443, 8080, 8443}
    if platforms and probe.get("reachable") and only_web:
        return (f"Shared edge of {', '.join(platforms)}: it answers an unknown hostname with the platform's own "
                f"response and exposes only web ports. Several unrelated customers share such IPs, so "
                f"{company_count} companies on it is not evidence of a relation.")
    if platforms:
        return f"Platform headers present ({', '.join(platforms)}), but the rest of the signals are mixed — likely a vendor edge."
    if {22, 3389} & set(ports):
        return ("Answers like a single server (administrative ports open, no platform edge headers). "
                "Hosts on it may genuinely share a machine — check the owner and whether the companies are related.")
    if probe.get("reachable"):
        return ("No platform edge headers: the IP answers for an unknown name with its own default response. "
                "It may be a shared VM or a dedicated server; the owner tells whether it is a cloud range.")
    return "Not enough signals: the IP did not answer the HTTPS probe."

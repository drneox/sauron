"""
Port Scanner Module
Primary engine: naabu binary (top-100 ports, fast parallel SYN/connect scan),
when installed and tools_naabu is on. Fallback: socket-based scanning of
COMMON_PORTS. Either way, open ports are enriched with banner grabbing and
unauthenticated-service probes by this module — the result contract is the
same regardless of engine.
"""
import asyncio
import re
import socket
import concurrent.futures
import logging
from typing import Any

from modules import tools_runner

logger = logging.getLogger(__name__)

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP/TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    3000: "Dev server / Grafana",
    3306: "MySQL",
    3389: "RDP",
    4848: "GlassFish Admin",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    7474: "Neo4j",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter / HTTP-Alt",
    9000: "Portainer / PHP-FPM",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    15672: "RabbitMQ Management",
    27017: "MongoDB",
    28017: "MongoDB HTTP",
}

RISKY_PORTS = {
    23, 135, 139, 445, 1433, 2375, 3306, 3389,
    4848, 5432, 5900, 6379, 7474, 8888, 9200,
    9300, 11211, 15672, 27017, 28017, 25, 111,
}

# Probes to detect unauthenticated access on specific ports
# (port, probe_bytes_or_None, unauth_marker_in_response)
_UNAUTH_PROBES: dict[int, tuple[bytes | None, str]] = {
    6379:  (b"PING\r\n",            "+PONG"),           # Redis: responds to PING
    27017: (None,                    "ismaster"),        # MongoDB: banner contains ismaster
    9200:  (None,                    '"cluster_name"'),  # Elasticsearch: JSON banner
    11211: (b"stats\r\n",           "STAT"),            # Memcached: stats command
    2375:  (b"GET /info HTTP/1.0\r\nHost: localhost\r\n\r\n", '"Containers"'),  # Docker API
    9000:  (b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",     "Portainer"),    # Portainer
    5601:  (b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",     "kibana"),       # Kibana
    8888:  (b"GET /api HTTP/1.0\r\nHost: localhost\r\n\r\n",  "kernels"),      # Jupyter
    15672: (b"GET /api/overview HTTP/1.0\r\nHost: localhost\r\n\r\n", "rabbitmq"), # RabbitMQ
}



def _scan_port(host: str, port: int, timeout: float = 1.5) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner  = _grab_banner(host, port)
            unauth  = _check_unauth(host, port, banner or "")
            return {
                "port":              port,
                "service":           service,
                "state":             "open",
                "banner":            banner,
                "risky":             port in RISKY_PORTS,
                "unauthenticated":   unauth,
            }
    except Exception:
        pass
    return None


def _grab_banner(host: str, port: int, timeout: float = 1.0) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 8080, 8888, 9000, 5601, 15672):
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:300] if banner else None
    except Exception:
        return None


def _check_unauth(host: str, port: int, existing_banner: str) -> bool:
    """Send a targeted probe and check if the service responds without auth."""
    if port not in _UNAUTH_PROBES:
        return False
    probe, marker = _UNAUTH_PROBES[port]
    # If banner already contains the marker (e.g. Redis +PONG) we're done
    if marker.lower() in existing_banner.lower():
        return True
    if probe is None:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((host, port))
        sock.sendall(probe)
        resp = sock.recv(512).decode("utf-8", errors="ignore")
        sock.close()
        return marker.lower() in resp.lower()
    except Exception:
        return False


def _enrich_port(host: str, port: int) -> dict:
    """Build the standard open-port entry for a port already proven open
    (e.g. by naabu): banner grab + unauthenticated-access probe."""
    banner = _grab_banner(host, port)
    return {
        "port":            port,
        "service":         COMMON_PORTS.get(port, "Unknown"),
        "state":           "open",
        "banner":          banner,
        "risky":           port in RISKY_PORTS,
        "unauthenticated": _check_unauth(host, port, banner or ""),
    }


def _naabu_open_ports(host: str) -> list[int] | None:
    """Open ports via the naabu binary, or None to fall back to sockets."""
    try:
        result = asyncio.run(tools_runner.naabu_scan(host))
    except Exception as e:
        logger.debug(f"[ports] naabu failed for {host}: {e} — falling back to sockets")
        return None
    if result.get("status") != "ok":
        logger.debug(f"[ports] naabu unavailable for {host}: "
                     f"{result.get('reason') or result.get('error')} — falling back to sockets")
        return None
    return result.get("ports") or []


def run(domain: str) -> dict[str, Any]:
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {
            "status": "error", "error": str(e),
            "open_ports": [], "ip": None, "total_open": 0,
            "risky_ports": 0, "unauthenticated_services": [],
            "risk": "low", "findings": [],
        }

    open_ports: list[dict] = []
    engine = "socket"
    naabu_ports = _naabu_open_ports(ip)
    if naabu_ports is not None:
        engine = "naabu"
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            open_ports = list(executor.map(lambda p: _enrich_port(ip, p), naabu_ports))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
            futures = {
                executor.submit(_scan_port, ip, port): port
                for port in COMMON_PORTS.keys()
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    risky   = [p for p in open_ports if p["risky"]]
    unauth  = [p for p in open_ports if p.get("unauthenticated")]

    risk = "low"
    findings: list[str] = []

    # Critical: unauthenticated dangerous services
    for p in unauth:
        svc = p["service"]
        findings.append(
            f"[CRITICAL] {svc} (port {p['port']}) is open and accessible WITHOUT authentication"
        )
        risk = "critical"

    # High: risky ports without unauth flag
    for p in risky:
        if p not in unauth:
            findings.append(
                f"Port {p['port']} ({p['service']}) is externally reachable — potentially dangerous"
            )
            if risk not in ("critical",):
                risk = "high" if len(risky) >= 2 else "medium"

    # Specific alerts
    for p in open_ports:
        port_num = p["port"]
        if port_num == 23:
            findings.append("Telnet (23) open — unencrypted, critical risk")
            risk = "critical"
        elif port_num == 2375:
            findings.append("Docker API (2375) open — allows full container control if unauthenticated")
            risk = "critical"
        elif port_num == 3389:
            findings.append("RDP (3389) exposed to internet — primary ransomware entry point")
        elif port_num == 22:
            # Remote administration reachable from the internet: a standard ASM
            # hardening finding (brute-force / credential-stuffing surface).
            # Kept out of RISKY_PORTS so it doesn't trip the "2+ risky ports => high" rule.
            banner = (p.get("banner") or "").strip()[:60]
            detail = f" — {banner}" if banner else ""
            m = re.search(r"OpenSSH_(\d+)\.(\d+)", banner)
            if m and (int(m.group(1)), int(m.group(2))) < (7, 4):
                detail += " (outdated OpenSSH)"
            findings.append(
                f"SSH (22) exposed to the internet{detail} — restrict by IP/VPN and enforce key-only auth"
            )
            if risk == "low":
                risk = "medium"
        elif port_num == 8888 and p.get("unauthenticated"):
            findings.append("Jupyter Notebook (8888) open without authentication — allows arbitrary code execution")
            risk = "critical"

    unauth_services = [
        {"port": p["port"], "service": p["service"], "banner": p.get("banner", "")[:100]}
        for p in unauth
    ]

    return {
        "status":                  "ok",
        "engine":                  engine,
        "ip":                      ip,
        "open_ports":              open_ports,
        "total_open":              len(open_ports),
        "risky_ports":             len(risky),
        "unauthenticated_services": unauth_services,
        "risk":                    risk,
        "findings":                findings,
    }


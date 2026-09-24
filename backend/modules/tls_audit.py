"""
TLS Configuration Audit Module
Checks cipher suites, protocol versions, and known TLS vulnerabilities
"""
import ssl
import socket
import httpx
import logging
from typing import Any

logger = logging.getLogger(__name__)

TIMEOUT = 10

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
    "RC4-MD5", "RC4-SHA", "DES-CBC3-SHA", "EXP-",
}

SECURE_CIPHER_KEYWORDS = {"AES256", "AES128", "CHACHA20", "GCM", "CCM"}

# TLS vulnerability checks via header/behavior
VULN_CHECKS = {
    "POODLE": "SSL 3.0 enabled",
    "BEAST": "TLS 1.0 with CBC cipher",
    "CRIME": "TLS compression enabled",
}


def _get_tls_info(hostname: str, port: int = 443) -> dict:
    result = {
        "connected": False,
        "protocol": None,
        "cipher_name": None,
        "cipher_bits": None,
        "cipher_version": None,
        "supports_tls13": False,
        "supports_tls12": False,
        "supports_tls11": False,
        "supports_tls10": False,
        "cert_sans": [],
        "cert_subject": None,
        "error": None,
    }

    # Try to connect and get current negotiated cipher
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["connected"] = True
                proto = ssock.version()
                result["protocol"] = proto
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_name"] = cipher[0]
                    result["cipher_version"] = cipher[1]
                    result["cipher_bits"] = cipher[2]
                cert = ssock.getpeercert()
                if cert:
                    san_list = []
                    for gtype, gval in cert.get("subjectAltName", []):
                        san_list.append(gval)
                    result["cert_sans"] = san_list
                    subject = dict(x[0] for x in cert.get("subject", []))
                    result["cert_subject"] = subject.get("commonName")
    except ssl.SSLError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    # Check protocol support individually
    for proto_name, min_version, max_version in [
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ]:
        try:
            # Protocol support only — certificate validity is checked elsewhere.
            # A bare SSLContext has an EMPTY trust store, so verifying here made
            # every probe fail and reported "neither TLS 1.2 nor 1.3" for all hosts.
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.minimum_version = min_version
            ctx2.maximum_version = max_version
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx2.wrap_socket(s, server_hostname=hostname):
                    if proto_name == "TLSv1.3":
                        result["supports_tls13"] = True
                    elif proto_name == "TLSv1.2":
                        result["supports_tls12"] = True
        except Exception:
            pass

    # The connection that already succeeded is ground truth for what the server speaks.
    if result["protocol"] == "TLSv1.3":
        result["supports_tls13"] = True
    elif result["protocol"] == "TLSv1.2":
        result["supports_tls12"] = True

    # Check TLS 1.0/1.1 support (deprecated)
    for proto_name, min_ver, max_ver in [
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ("TLSv1",   ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1),
    ]:
        try:
            ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx3.minimum_version = min_ver
            ctx3.maximum_version = max_ver
            ctx3.check_hostname = False
            ctx3.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx3.wrap_socket(s, server_hostname=hostname):
                    if proto_name == "TLSv1.1":
                        result["supports_tls11"] = True
                    else:
                        result["supports_tls10"] = True
        except Exception:
            pass

    return result


def _check_hsts(domain: str) -> dict:
    try:
        r = httpx.get(f"https://{domain}", timeout=TIMEOUT, verify=False, follow_redirects=True)
        hsts = r.headers.get("Strict-Transport-Security", "")
        preload = "preload" in hsts.lower()
        include_subdomains = "includesubdomains" in hsts.lower()
        max_age = 0
        import re
        m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if m:
            max_age = int(m.group(1))
        return {
            "header": hsts or None,
            "present": bool(hsts),
            "max_age": max_age,
            "include_subdomains": include_subdomains,
            "preload": preload,
            "preload_eligible": preload and include_subdomains and max_age >= 31536000,
        }
    except Exception:
        return {"header": None, "present": False, "max_age": 0,
                "include_subdomains": False, "preload": False, "preload_eligible": False,
                "error": True}


def run(domain: str) -> dict[str, Any]:
    findings: list[str] = []
    risk = "low"

    tls = _get_tls_info(domain)
    hsts = _check_hsts(domain)

    if not tls["connected"]:
        return {
            "status": "error",
            "error": tls.get("error", "Could not connect"),
            "protocol": None,
            "cipher": None,
            "supports_tls13": False,
            "supports_tls12": False,
            "supports_tls11": False,
            "supports_tls10": False,
            "deprecated_protocols": [],
            "weak_cipher": False,
            "hsts": hsts,
            "risk": "medium",
            "findings": ["TLS connection failed — HTTPS may not be configured"],
        }

    deprecated = []
    if tls["supports_tls10"]:
        deprecated.append("TLS 1.0")
        findings.append("TLS 1.0 supported — deprecated, vulnerable to BEAST/POODLE")
        risk = "medium"
    if tls["supports_tls11"]:
        deprecated.append("TLS 1.1")
        findings.append("TLS 1.1 supported — deprecated since RFC 8996")
        risk = max(risk, "medium", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r,0))

    # Cipher check
    cipher_name = tls.get("cipher_name", "") or ""
    weak_cipher = any(w in cipher_name.upper() for w in WEAK_CIPHERS)
    if weak_cipher:
        findings.append(f"Weak cipher suite in use: {cipher_name}")
        risk = "high"

    # Key size
    bits = tls.get("cipher_bits")
    if bits and bits < 128:
        findings.append(f"Cipher key length too short: {bits} bits")
        risk = "high"

    # HSTS
    if hsts.get("error"):
        pass  # request failed: absence of the header is unknown, don't claim it
    elif not hsts["present"]:
        findings.append("HSTS header missing — no forced HTTPS enforcement")
        risk = max(risk, "medium", key=lambda r: {"low":0,"medium":1,"high":2,"critical":3}.get(r,0))
    elif hsts["max_age"] < 31536000:
        findings.append(f"HSTS max-age too short: {hsts['max_age']}s (recommended ≥ 1 year)")
    elif not hsts["include_subdomains"]:
        findings.append("HSTS missing includeSubDomains")

    if not tls["supports_tls13"] and not tls["supports_tls12"]:
        findings.append("Neither TLS 1.2 nor TLS 1.3 supported — modern client compatibility issues")
        risk = "high"

    return {
        "status": "ok",
        "protocol": tls["protocol"],
        "cipher": {
            "name": tls["cipher_name"],
            "bits": tls["cipher_bits"],
            "version": tls["cipher_version"],
        },
        "supports_tls13": tls["supports_tls13"],
        "supports_tls12": tls["supports_tls12"],
        "supports_tls11": tls["supports_tls11"],
        "supports_tls10": tls["supports_tls10"],
        "deprecated_protocols": deprecated,
        "weak_cipher": weak_cipher,
        "hsts": hsts,
        "risk": risk,
        "findings": findings,
    }

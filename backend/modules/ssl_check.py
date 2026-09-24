"""
SSL/TLS Certificate Analysis Module
Checks certificate validity, chain, protocols, and cipher suites
"""
import ssl
import socket
import datetime
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_certificate(hostname: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.create_connection((hostname, port), timeout=10),
        server_hostname=hostname,
    )
    cert = conn.getpeercert()
    cipher = conn.cipher()
    version = conn.version()
    conn.close()
    return {"cert": cert, "cipher": cipher, "version": version}


def _serves_tls(hostname: str) -> bool:
    try:
        _get_certificate(hostname)
        return True
    except Exception:
        return False


def _check_deprecated_protocols(hostname: str) -> list[str]:
    deprecated = []
    for protocol, name in [
        (ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None, "TLS 1.0"),
    ]:
        if protocol is None:
            continue
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=5),
                server_hostname=hostname,
            )
            conn.close()
            deprecated.append(name)
        except Exception:
            pass
    return deprecated


def run(domain: str, port: int = 443) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "ok",
        "has_ssl": False,
        "subject": {},
        "issuer": {},
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "san": [],
        "cipher": None,
        "protocol": None,
        "self_signed": False,
        "expired": False,
        "deprecated_protocols": [],
        "risk": "low",
        "findings": [],
    }

    try:
        data = _get_certificate(domain, port)
        cert = data["cert"]
        result["has_ssl"] = True

        # Subject & Issuer
        result["subject"] = dict(x[0] for x in cert.get("subject", []))
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))

        # Dates
        not_before = ssl.cert_time_to_seconds(cert["notBefore"])
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        now = datetime.datetime.utcnow().timestamp()

        result["valid_from"] = datetime.datetime.utcfromtimestamp(not_before).isoformat()
        result["valid_to"] = datetime.datetime.utcfromtimestamp(not_after).isoformat()
        result["days_remaining"] = int((not_after - now) / 86400)

        # SANs
        san_list = []
        for key, value in cert.get("subjectAltName", []):
            if key == "DNS":
                san_list.append(value)
        result["san"] = san_list

        # Cipher & protocol
        result["cipher"] = data["cipher"][0] if data["cipher"] else None
        result["protocol"] = data["version"]

        # Self-signed check
        result["self_signed"] = result["subject"] == result["issuer"]

        # Expired
        result["expired"] = result["days_remaining"] < 0

        # Risk assessment
        if result["expired"]:
            result["risk"] = "critical"
            result["findings"].append("SSL certificate has expired")
        elif result["days_remaining"] < 14:
            result["risk"] = "critical"
            result["findings"].append(f"SSL certificate expires in {result['days_remaining']} days")
        elif result["days_remaining"] < 30:
            result["risk"] = "high"
            result["findings"].append(f"SSL certificate expires soon ({result['days_remaining']} days)")

        if result["self_signed"]:
            result["risk"] = "high"
            result["findings"].append("Self-signed certificate detected — not trusted by browsers")

        # Deprecated protocols
        result["deprecated_protocols"] = _check_deprecated_protocols(domain)
        if result["deprecated_protocols"]:
            result["findings"].append(
                f"Deprecated TLS protocols supported: {', '.join(result['deprecated_protocols'])}"
            )
            if result["risk"] in ("low", "medium"):
                result["risk"] = "medium"

        # Weak cipher check
        if result["cipher"] and any(
            weak in result["cipher"].upper() for weak in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
        ):
            result["findings"].append(f"Weak cipher suite detected: {result['cipher']}")
            result["risk"] = "high"

    except ssl.SSLCertVerificationError as e:
        # The server answered with a certificate that clients reject (hostname
        # mismatch, untrusted chain, ...): a real, user-visible certificate defect.
        result["status"] = "ssl_error"
        result["error"] = str(e)
        result["risk"] = "high"
        result["findings"].append(
            f"SSL certificate validation failed: {e.verify_message or e.reason or 'untrusted certificate'}"
        )
    except ssl.SSLError as e:
        # The server refused the handshake itself (handshake_failure / internal
        # error alert): typically a CDN with no certificate configured for this
        # hostname — HTTPS isn't served here, which is not a broken certificate.
        result["status"] = "ssl_error"
        result["error"] = str(e)
        result["risk"] = "medium"
        note = ""
        if not domain.startswith("www.") and _serves_tls(f"www.{domain}"):
            note = f" (www.{domain} does serve HTTPS)"
        result["findings"].append(
            f"TLS handshake refused by the server — HTTPS is not served on this hostname{note}"
        )
    except ConnectionRefusedError:
        result["status"] = "no_ssl"
        result["has_ssl"] = False
        result["risk"] = "high"
        result["findings"].append("Port 443 not open — no HTTPS detected")
    except Exception as e:
        logger.error(f"[ssl] {domain}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    return result

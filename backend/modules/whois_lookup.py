"""
WHOIS Lookup Module
Retrieves domain registration information
"""
import whois
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def run(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "ok",
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "registrant_country": None,
        "emails": [],
        "dnssec": None,
        "org": None,
        "raw": None,
        "risk": "low",
        "findings": [],
    }
    try:
        w = whois.whois(domain)
        result["registrar"] = w.registrar
        result["org"] = w.org

        def _parse_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.isoformat()
            return str(d) if d else None

        result["creation_date"] = _parse_date(w.creation_date)
        result["expiration_date"] = _parse_date(w.expiration_date)
        result["updated_date"] = _parse_date(w.updated_date)
        result["name_servers"] = (
            [ns.lower() for ns in w.name_servers] if w.name_servers else []
        )
        result["registrant_country"] = w.country
        result["emails"] = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
        result["dnssec"] = w.dnssec

        # Risk: domain expiring in < 30 days
        if w.expiration_date:
            exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            if isinstance(exp, datetime):
                days_left = (exp - datetime.utcnow()).days
                if days_left < 30:
                    result["risk"] = "critical"
                    result["findings"].append(
                        f"Domain expires in {days_left} day(s) — renew immediately, "
                        "an expired domain can be re-registered by an attacker (hijack risk)"
                    )
                elif days_left < 90:
                    result["risk"] = "medium"
                    result["findings"].append(
                        f"Domain expires in {days_left} day(s) — schedule renewal soon"
                    )

    except Exception as e:
        logger.error(f"[whois] {domain}: {e}")
        result["status"] = "error"
        result["error"] = str(e)

    return result

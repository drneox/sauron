"""
Compliance mapping — tags findings with the security frameworks they relate to.

Frameworks covered: NIST-CSF, ISO-27001, PCI-DSS, CIS.

The mapping is deliberately rule-based and static (not exhaustive):
  1. Module-level rules (MODULE_FRAMEWORKS): the framework(s) a module's
     findings generally map to — e.g. TLS/headers/cookies/email hardening
     gaps map to NIST-CSF + ISO-27001 + CIS controls.
  2. Text overrides (TEXT_RULES): keyword rules applied to the finding text
     that can ADD frameworks — e.g. anything mentioning an exposed secret or
     credential also maps to PCI-DSS (sensitive-data protection), anything
     about encryption/TLS also maps to PCI-DSS requirement 4.

Findings with no rule match get [] — the UI shows them as untagged.
"""
import re

FRAMEWORKS = ("NIST-CSF", "ISO-27001", "PCI-DSS", "CIS")

# Module-level mapping, keyed by module name as stored in scan results.
# Criterion:
#   - Transport/security hardening (ssl, tls, headers, cookies, dnssec,
#     email): NIST-CSF PR.DS / ISO A.8.24 / CIS — plus PCI-DSS req. 4 via
#     the text rule when encryption is explicitly mentioned.
#   - Secrets/credentials/exposed sensitive files: NIST-CSF + ISO-27001 +
#     PCI-DSS (sensitive-data exposure).
#   - Known vulnerabilities (nuclei, frontend_cve): NIST-CSF + ISO-27001 +
#     CIS (vulnerability management control).
#   - Attack-surface exposure (open ports, admin panels, API docs): NIST-CSF
#     ID.AM / CIS inventory & control.
#   - Breach/leak evidence: NIST-CSF + ISO-27001 + PCI-DSS.
#   - Pure inventory modules (whois, dns, subdomains, tech, waf, reverse_ip,
#     mobile_apps) intentionally map to nothing — inventory is not a control
#     gap by itself.
MODULE_FRAMEWORKS: dict[str, list[str]] = {
    "ssl": ["NIST-CSF", "ISO-27001", "CIS"],
    "tls": ["NIST-CSF", "ISO-27001", "PCI-DSS", "CIS"],
    "headers": ["NIST-CSF", "ISO-27001", "CIS"],
    "cookies": ["NIST-CSF", "ISO-27001", "CIS"],
    "cors": ["NIST-CSF", "ISO-27001", "CIS"],
    "dnssec": ["NIST-CSF", "ISO-27001", "CIS"],
    "email": ["NIST-CSF", "ISO-27001", "CIS"],
    "ports": ["NIST-CSF", "CIS"],
    "admin": ["NIST-CSF", "CIS"],
    "api_exposure": ["NIST-CSF", "CIS"],
    "js_secrets": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "secret_verification": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "exposed": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "wayback": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "breach": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "nuclei": ["NIST-CSF", "ISO-27001", "CIS"],
    "frontend_cve": ["NIST-CSF", "ISO-27001", "CIS"],
    "smart_fuzz": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "cloud_storage": ["NIST-CSF", "ISO-27001", "PCI-DSS"],
    "blacklist": ["NIST-CSF", "ISO-27001"],
    "agent": ["NIST-CSF", "ISO-27001"],
}

# Text-level rules: (compiled regex on lowercased finding text, frameworks to
# ADD). Applied on top of the module mapping, so e.g. an ssl finding that
# mentions encryption also picks up PCI-DSS.
TEXT_RULES: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"\b(secret|api[_ -]?key|token|credential|password|private key)\b"),
     ["ISO-27001", "PCI-DSS"]),
    (re.compile(r"\b(tls|ssl|encrypt|cipher|certificate)\b"),
     ["PCI-DSS"]),
    (re.compile(r"\b(cve-\d{4}-\d+|vulnerab|exploit)\b"),
     ["CIS"]),
    (re.compile(r"\b(bucket|s3|public access|card|pii|personal data)\b"),
     ["PCI-DSS"]),
]


def frameworks_for(module: str, text: str) -> list[str]:
    """Compliance frameworks a finding maps to (deduplicated, canonical order)."""
    tags = set(MODULE_FRAMEWORKS.get(module, []))
    lowered = (text or "").lower()
    for pattern, fws in TEXT_RULES:
        if pattern.search(lowered):
            tags.update(fws)
    return [fw for fw in FRAMEWORKS if fw in tags]

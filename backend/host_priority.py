"""Which discovered hosts deserve a deep look first.

Fan-out and chained evaluation are capped, so the order decides which hosts
are covered when a domain has more subdomains than the cap. Ordering by name
would starve everything late in the alphabet, so hosts are ranked by how
likely they are to carry weaknesses, from signals available at discovery
time (no extra network traffic):

  - non-production environments (cert, qa, uat, dev, stg...) usually run
    with weaker protections, debug settings and test data
  - administrative / sensitive-function names (admin, vpn, sso, jenkins...)
  - the discovery source already flagged the host as sensitive
  - a previous light evaluation found it alive or with findings

The score only orders hosts; it never excludes one.
"""
import re

NON_PROD_TOKENS = frozenset({
    "cert", "qa", "uat", "dev", "desa", "des", "stg", "stage", "staging", "test",
    "testing", "sandbox", "sbx", "preprod", "pre", "beta", "demo", "homolog",
    "hml", "lab", "poc", "temp", "tmp", "old", "legacy", "backup", "bak",
})

SENSITIVE_TOKENS = frozenset({
    "admin", "administrator", "backoffice", "intranet", "vpn", "sso", "login",
    "auth", "oauth", "jenkins", "gitlab", "git", "grafana", "kibana", "jira",
    "confluence", "sonar", "nexus", "artifactory", "phpmyadmin", "db", "sql",
    "mail", "webmail", "ftp", "sftp", "ssh", "rdp", "vault", "monitor",
    "internal", "api", "gateway", "portal", "console", "dashboard", "manage",
})

NON_PROD_WEIGHT = 3
SENSITIVE_WEIGHT = 2
SOURCE_SENSITIVE_WEIGHT = 3
ALIVE_WEIGHT = 2
EVAL_RISK_WEIGHT = {"critical": 5, "high": 4, "medium": 3}

_TOKEN_SPLIT = re.compile(r"[.\-_0-9]+")


def _tokens(host: str, apex: str) -> set[str]:
    """Labels of `host` below the apex, split on separators and digits
    ("app2-qa.example.com" -> {"app", "qa"})."""
    host = host.lower().rstrip(".")
    apex = apex.lower().rstrip(".")
    if apex and host.endswith("." + apex):
        host = host[: -(len(apex) + 1)]
    return {t for t in _TOKEN_SPLIT.split(host) if t}


def host_priority(host: str, apex: str, entry: dict | None = None,
                  evaluated: dict | None = None) -> int:
    """Higher = look at it sooner. `entry` is the subdomain-enumeration row for
    the host; `evaluated` its subdomain_eval row from an earlier scan, if any."""
    tokens = _tokens(host, apex)
    score = 0
    if tokens & NON_PROD_TOKENS:
        score += NON_PROD_WEIGHT
    if tokens & SENSITIVE_TOKENS:
        score += SENSITIVE_WEIGHT
    if entry and entry.get("sensitive"):
        score += SOURCE_SENSITIVE_WEIGHT
    if evaluated:
        if evaluated.get("alive"):
            score += ALIVE_WEIGHT
        score += EVAL_RISK_WEIGHT.get(evaluated.get("risk"), 0)
    return score

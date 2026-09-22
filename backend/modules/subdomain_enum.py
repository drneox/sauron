"""
Subdomain Enumeration Module
Uses DNS brute-force with a wordlist + passive multi-source aggregation
(crt.sh, certspotter, wayback, grep.app, hackertarget — see discovery_sources).
If the subfinder binary is installed (and tools_subfinder is on), it runs as
one more passive source and its hits are tagged with source "subfinder".
"""
import asyncio
import httpx
import dns.resolver
import logging
from typing import Any

from modules import tools_runner
from modules.discovery_sources import (
    certspotter_subs,
    crtsh_subs,
    grepapp_hosts,
    otx_subs,
    securitytrails_subs,
    wayback_subs,
)

logger = logging.getLogger(__name__)

# Common subdomain wordlist
COMMON_SUBS = [
    # Web basics
    "www", "www2", "www3", "web", "web1", "web2", "m", "mobile", "wap",
    # Mail
    "mail", "mail2", "webmail", "smtp", "imap", "pop", "pop3", "mx", "mx1", "mx2",
    "exchange", "owa", "outlook", "autodiscover", "autoconfig",
    # Dev / staging
    "dev", "dev1", "dev2", "develop", "development",
    "test", "test1", "test2", "testing",
    "stage", "staging", "stg", "uat", "qa", "sandbox",
    "alpha", "beta", "demo", "preview", "pre", "preprod",
    "old", "backup", "archive", "legacy", "classic",
    # Infrastructure
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "ftp", "sftp", "files", "file", "download", "downloads",
    "vpn", "vpn1", "vpn2", "remote", "rdp", "ssh",
    "server", "server1", "server2", "host", "hosting",
    "lb", "load", "balancer", "proxy", "gateway", "router", "fw", "firewall",
    # CDN / static
    "cdn", "static", "assets", "media", "img", "images", "image",
    "video", "videos", "audio", "content", "upload", "uploads",
    "storage", "s3", "files",
    # Apps / services
    "api", "api2", "api3", "apis", "rest", "graphql", "grpc",
    "app", "app1", "app2", "apps", "application",
    "shop", "store", "cart", "order", "orders", "checkout", "pay", "payment",
    "blog", "news", "press", "media", "pub",
    "support", "help", "helpdesk", "ticket", "tickets",
    "docs", "doc", "documentation", "wiki", "kb", "knowledge",
    "forum", "community", "discuss", "discord",
    "status", "monitor", "monitoring", "uptime", "health",
    "secure", "ssl",
    # Admin / portals
    "admin", "admin1", "admin2", "administrator", "administration",
    "portal", "panel", "dashboard", "console",
    "cp", "cpanel", "whm", "webdisk", "plesk", "directadmin",
    "manage", "management", "manager", "control",
    "login", "auth", "sso", "oauth", "identity", "id", "accounts", "account",
    # DevOps / internal tools
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "jira", "confluence", "wiki", "intranet", "internal", "corp", "office", "int",
    "ci", "cd", "jenkins", "travis", "circleci", "teamcity", "drone",
    "sonar", "sonarqube", "artifactory", "nexus",
    "kubernetes", "k8s", "docker", "registry", "harbor", "rancher", "openshift",
    "grafana", "kibana", "prometheus", "elastic", "elasticsearch", "logstash",
    # Databases / cache
    "db", "db1", "db2", "database", "mysql", "postgres", "mongo", "mongodb",
    "redis", "cache", "memcached",
    "queue", "mq", "rabbitmq", "kafka", "broker",
    # API versioning
    "v1", "v2", "v3", "v4",
    # Communication
    "calendar", "cal", "meet", "chat", "slack", "teams",
    "crm", "erp", "hr",
    # Misc
    "search", "microservice", "service", "services",
    "sandbox", "lab", "labs",
]


async def _resolve_async(domain: str, semaphore: asyncio.Semaphore) -> dict | None:
    async with semaphore:
        # Use get_running_loop() — safe inside a coroutine (get_event_loop() is deprecated in 3.10+)
        loop = asyncio.get_running_loop()
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = await loop.run_in_executor(None, lambda: resolver.resolve(domain, "A"))
            ips = [str(r) for r in answers]
            return {"subdomain": domain, "ips": ips, "status": "active"}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return None
        except Exception:
            return None


async def _hackertarget(domain: str) -> set[str]:
    """Query HackerTarget API (free tier, no key needed) for subdomains"""
    subdomains = set()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers={"User-Agent": "Mozilla/5.0 (compatible; DumbAuditor/1.0)"},
            )
            if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                for line in resp.text.splitlines():
                    if "," in line:
                        host = line.split(",")[0].strip()
                        if host.endswith(f".{domain}") or host == domain:
                            subdomains.add(host)
    except Exception as e:
        logger.debug(f"[hackertarget] {domain}: {e}")
    return subdomains


async def _subfinder(domain: str) -> set[str]:
    """subfinder binary as one more passive source (skipped if absent/disabled)."""
    try:
        result = await tools_runner.subfinder_subs(domain)
        if result.get("status") != "ok":
            logger.debug(f"[subfinder] {domain}: {result.get('reason') or result.get('error')}")
            return set()
        return set(result.get("subdomains") or [])
    except Exception as e:
        logger.debug(f"[subfinder] {domain}: {e}")
        return set()


async def _run_async(domain: str) -> dict[str, Any]:
    # Query all passive sources in parallel; each is fault-tolerant and
    # returns a set of hosts. Track which sources saw each subdomain.
    source_funcs = {
        "crt.sh": crtsh_subs(domain),
        "certspotter": certspotter_subs(domain),
        "wayback": wayback_subs(domain),
        "hackertarget": _hackertarget(domain),
        "grep.app": grepapp_hosts(domain),
        "securitytrails": securitytrails_subs(domain),
        "otx": otx_subs(domain),
        "subfinder": _subfinder(domain),
    }
    gathered = await asyncio.gather(*source_funcs.values(), return_exceptions=True)

    sources_map: dict[str, set[str]] = {}
    source_counts: dict[str, int] = {}
    for source, result in zip(source_funcs.keys(), gathered):
        if isinstance(result, Exception):
            logger.debug(f"[subdomains] source {source} failed for {domain}: {result}")
            source_counts[source] = 0
            continue
        # grep.app may return unrelated hosts — keep only this domain's
        hosts = {h for h in result if h == domain or h.endswith(f".{domain}")}
        source_counts[source] = len(hosts)
        for host in hosts:
            sources_map.setdefault(host, set()).add(source)

    # Build full list merging all sources
    passive_subs = sorted(sources_map)
    brute_subs = [f"{sub}.{domain}" for sub in COMMON_SUBS]
    all_candidates = list(set(passive_subs + brute_subs))

    semaphore = asyncio.Semaphore(30)
    tasks = [_resolve_async(sub, semaphore) for sub in all_candidates]
    results = await asyncio.gather(*tasks)

    found = [r for r in results if r is not None]
    for item in found:
        item["sources"] = sorted(sources_map.get(item["subdomain"], set()))

    # Risk: any sensitive subdomain exposed
    risk = "low"
    findings = []
    sensitive_keywords = ["admin", "dev", "test", "staging", "internal", "corp", "db",
                           "database", "backup", "old", "legacy", "git", "jenkins", "ci",
                           "kubernetes", "k8s", "docker", "vpn", "intranet"]

    for item in found:
        for keyword in sensitive_keywords:
            if keyword in item["subdomain"].split(".")[0].lower():
                item["sensitive"] = True
                risk = "high"
                findings.append(f"Sensitive subdomain exposed: {item['subdomain']}")
                break
        else:
            item["sensitive"] = False

    return {
        "status": "ok",
        "count": len(found),
        "subdomains": found,
        "crt_sh_count": source_counts["crt.sh"],
        "hackertarget_count": source_counts["hackertarget"],
        "certspotter_count": source_counts["certspotter"],
        "wayback_count": source_counts["wayback"],
        "grepapp_count": source_counts["grep.app"],
        "subfinder_count": source_counts["subfinder"],
        "passive_count": len(passive_subs),
        "brute_force_count": len([r for r in found if r["subdomain"] not in passive_subs]),
        "risk": risk,
        "findings": findings,
    }


def run(domain: str) -> dict[str, Any]:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_run_async(domain))
        loop.close()
        return result
    except Exception as e:
        logger.error(f"[subdomains] {domain}: {e}")
        return {"status": "error", "error": str(e), "subdomains": [], "count": 0}

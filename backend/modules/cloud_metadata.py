"""
cloud_metadata.py — Cloud storage bucket exposure detection.

Three complementary sources, all optional:

  1. S3Scanner (optional binary)
     Go tool that checks real S3/GCS/DigitalOcean/Linode bucket permissions.
     Install: brew install s3scanner | go install github.com/sa7mon/s3scanner@latest
     Runs all candidate names through the scanner with proper permission checks.

  2. GrayhatWarfare API (optional)
     Real-time index of millions of known public buckets by keyword.
     Activate: export GRAYHATWARFARE_KEY="your_key"   (free at buckets.grayhatwarfare.com)

  3. Direct HTTP probe (always runs)
     Probes AWS S3 / GCS / Azure Blob endpoints for each candidate name.
     Uses tldextract to correctly handle ccTLDs (.edu.pe, .co.uk, .com.ar, etc.)
     Candidate names generated from the cloud_enum wordlist (~350 mutations).

Severity:
  critical  :  bucket public + listable (ListBucketResult / EnumerationResults / S3Scanner READ)
  high      :  bucket publicly accessible but content not listed
  info/medium:  bucket exists but private (403)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import httpx
import tldextract

logger = logging.getLogger(__name__)

TIMEOUT           = httpx.Timeout(8.0, connect=5.0)
CONCURRENCY       = 20
S3SCANNER_TIMEOUT = 90

GRAYHATWARFARE_KEY = os.environ.get("GRAYHATWARFARE_KEY", "")

# ── cloud_enum wordlist (github.com/initstring/cloud_enum, MIT) ───────────────
_CLOUD_ENUM_WORDS: tuple[str, ...] = (
    "0", "001", "002", "01", "02", "1", "2",
    "2014", "2015", "2016", "2017", "2018", "2019",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "3", "4", "5", "6", "7", "8", "9",
    "access-logs", "accounting", "admin", "administrator",
    "alpha", "analytics", "android", "api", "app", "appengine",
    "archive", "artifacts", "assets", "attachments",
    "audit", "audit-logs", "aws", "aws-billing", "aws-logs",
    "azure", "azure-logs", "backup", "backups", "bak",
    "bamboo", "beta", "billing", "blob", "blog", "bucket",
    "build", "builds", "cache", "cdn", "chef", "client",
    "cloud", "common", "conf", "confidential", "config", "configuration",
    "content", "core", "corp", "corporate", "customer",
    "data", "data-private", "data-public",
    "database", "db", "debug", "demo",
    "dev", "developer", "developers", "development", "devops",
    "directory", "dist", "dl", "dns", "docker", "docs",
    "download", "downloads", "dr", "elastic", "emails",
    "es", "events", "export", "files", "finance",
    "functions", "gateway", "git", "github", "gitlab",
    "graphql", "help", "hidden", "hr", "iam",
    "images", "img", "infra", "internal",
    "internal-dist", "internal-repo", "internal-tools",
    "ios", "jenkins", "jira", "js", "k8s",
    "key", "keys", "kube", "kubernetes",
    "ldap", "logs", "logstash", "mail", "main", "manuals",
    "media", "ml", "mobile", "monitoring", "my", "mysql",
    "ops", "packages", "panel", "passwords",
    "photos", "pics", "postgres",
    "pre-prod", "preprod", "presentations", "preview",
    "private", "prod", "product", "production", "products",
    "project", "projects", "public", "qa",
    "repo", "reports", "resources", "root",
    "s3", "scripts", "sec", "secret", "secrets",
    "secure", "security", "service", "services",
    "share", "shared", "shop", "site", "sitemaps",
    "snapshots", "source", "source-code",
    "sql", "ssh", "stage", "staging",
    "static", "stats", "storage", "store",
    "support", "svn", "tasks", "temp", "templates",
    "terraform", "test", "themes", "tmp", "trace",
    "training", "uploads", "userfiles", "users",
    "videos", "vm", "web", "website", "wp", "www",
)

# Cloud storage endpoint templates (provider_code, url_template, list_marker)
_ENDPOINTS: list[tuple[str, str, str]] = [
    ("aws",   "https://{name}.s3.amazonaws.com/",                "ListBucketResult"),
    ("aws",   "https://s3.amazonaws.com/{name}/",                "ListBucketResult"),
    ("gcs",   "https://storage.googleapis.com/{name}/",          "ListBucketResult"),
    ("gcs",   "https://{name}.storage.googleapis.com/",          "ListBucketResult"),
    ("azure", "https://{name}.blob.core.windows.net/?comp=list", "EnumerationResults"),
    ("azure", "https://{name}.blob.core.windows.net/",           "EnumerationResults"),
]

_GHW_URL = "https://buckets.grayhatwarfare.com/api/v2/buckets/{keyword}"


# ── Domain parsing ────────────────────────────────────────────────────────────

def _org_names(domain: str) -> list[str]:
    """
    Extract the registered domain name using tldextract.
    Handles multi-part ccTLDs:
      mibanco.edu.pe   → ['mibanco']
      api.example.com  → ['example', 'api']
      store.brand.co.uk → ['brand', 'store']
    """
    ext = tldextract.extract(domain.removeprefix("www."))
    candidates: list[str] = []
    if ext.domain:
        candidates.append(ext.domain.lower())
    if ext.subdomain:
        sub = ext.subdomain.split(".")[-1].lower()
        if len(sub) > 2 and sub not in ("www", "mail", "smtp", "ftp"):
            candidates.append(sub)
    return list(dict.fromkeys(candidates))


def _candidate_names(domain: str) -> list[str]:
    """
    Generate candidate bucket names: {org}-{word} and {word}-{org}
    using the full cloud_enum wordlist.
    """
    org_names = _org_names(domain)
    seen: set[str] = set()
    names: list[str] = []

    def _add(s: str) -> None:
        s = re.sub(r'[^a-z0-9\-]', '-', s.lower()).strip("-")
        s = re.sub(r'-{2,}', '-', s)
        if s not in seen and re.match(r'^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$', s):
            seen.add(s)
            names.append(s)

    prefix_words = {
        "backup", "dev", "prod", "staging", "data", "assets",
        "static", "media", "uploads", "files", "api", "web",
    }
    for base in org_names:
        _add(base)
        for word in _CLOUD_ENUM_WORDS:
            _add(f"{base}-{word}")
            if word in prefix_words:
                _add(f"{word}-{base}")

    return names[:200]


# ── S3Scanner ─────────────────────────────────────────────────────────────────

def _find_s3scanner() -> str | None:
    p = shutil.which("s3scanner")
    if p:
        return p
    for candidate in [
        "/usr/local/bin/s3scanner",
        "/usr/bin/s3scanner",
        str(Path.home() / "go" / "bin" / "s3scanner"),
        str(Path.home() / ".local" / "bin" / "s3scanner"),
    ]:
        if Path(candidate).exists():
            return candidate
    return None


def _perm_public(value: str) -> bool:
    v = (value or "").upper()
    return any(x in v for x in ("PUBLIC", "READ", "WRITE", "FULL_CONTROL"))


def _run_s3scanner(candidates: list[str]) -> list[dict]:
    """Run s3scanner against all candidates. Returns list of exposure dicts."""
    binary = _find_s3scanner()
    if not binary:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(candidates))
        tmp = f.name

    hits: list[dict] = []
    for provider in ("aws", "gcp"):
        try:
            proc = subprocess.run(
                [binary, "-bucket-file", tmp, "-json",
                 "-threads", "10", "-provider", provider],
                capture_output=True, text=True,
                timeout=S3SCANNER_TIMEOUT,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                b = data.get("bucket", {})
                if b.get("exists") != 1:
                    continue

                name   = b.get("name", "")
                region = b.get("region", "")
                perms  = {k: v for k, v in b.items() if k.startswith("perm")}
                public = [k for k, v in perms.items() if _perm_public(v)]

                if public:
                    sev = "critical" if any("read" in p.lower() for p in public) else "high"
                    url = (
                        f"https://{name}.s3.amazonaws.com/"
                        if provider == "aws"
                        else f"https://storage.googleapis.com/{name}/"
                    )
                    hits.append({
                        "name":     name,
                        "provider": provider,
                        "url":      url,
                        "status":   f"public ({', '.join(public)})",
                        "severity": sev,
                        "source":   "s3scanner",
                        "region":   region,
                    })
                else:
                    hits.append({
                        "name":     name,
                        "provider": provider,
                        "url":      "",
                        "status":   "exists_private",
                        "severity": "info",
                        "source":   "s3scanner",
                        "region":   region,
                    })
        except subprocess.TimeoutExpired:
            logger.warning("s3scanner timed out (provider=%s)", provider)
        except Exception as exc:
            logger.debug("s3scanner error: %s", exc)

    try:
        os.unlink(tmp)
    except Exception:
        pass
    return hits


# ── GrayhatWarfare ────────────────────────────────────────────────────────────

async def _ghw_search(client: httpx.AsyncClient, keyword: str) -> list[dict]:
    if not GRAYHATWARFARE_KEY:
        return []
    try:
        r = await client.get(
            _GHW_URL.format(keyword=keyword),
            headers={"Authorization": f"Bearer {GRAYHATWARFARE_KEY}"},
            timeout=httpx.Timeout(12.0),
        )
        if r.status_code != 200:
            return []
        return [
            {
                "name":     b.get("bucket", ""),
                "provider": b.get("type", "aws").lower(),
                "url":      b.get("url", ""),
                "status":   "public_listable",
                "severity": "critical",
                "source":   "grayhatwarfare",
            }
            for b in r.json().get("buckets", [])[:20]
        ]
    except Exception:
        return []


# ── Direct HTTP probe ─────────────────────────────────────────────────────────

async def _probe(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    name: str,
    provider: str,
    url: str,
    list_marker: str,
) -> dict | None:
    async with sem:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                sev    = "critical" if list_marker in r.text else "high"
                status = "public_listable" if sev == "critical" else "public_accessible"
                return {"name": name, "provider": provider, "url": url,
                        "status": status, "severity": sev, "source": "probe"}
            if r.status_code == 403:
                return {"name": name, "provider": provider, "url": url,
                        "status": "exists_private", "severity": "info", "source": "probe"}
        except Exception:
            pass
    return None


# ── Orchestrator ──────────────────────────────────────────────────────────────

async def _run_async(domain: str, s3scanner_hits: list[dict]) -> dict[str, Any]:
    names   = _candidate_names(domain)
    keyword = (_org_names(domain) or [names[0]])[0]
    sem     = asyncio.Semaphore(CONCURRENCY)

    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
    ) as client:
        ghw_hits = await _ghw_search(client, keyword)
        tasks = [
            _probe(client, sem, name, provider, tmpl.format(name=name), marker)
            for name in names
            for provider, tmpl, marker in _ENDPOINTS
        ]
        probe_results = await asyncio.gather(*tasks)

    all_hits = s3scanner_hits + ghw_hits + [r for r in probe_results if r]

    # Deduplicate — keep highest severity per (name, provider)
    sev_order = {"critical": 3, "high": 2, "info": 0}
    seen: dict[str, dict] = {}
    for h in all_hits:
        key = f"{h['name']}|{h['provider']}"
        if key not in seen or sev_order.get(h["severity"], 0) > sev_order.get(seen[key]["severity"], 0):
            seen[key] = h

    exposed  = [h for h in seen.values() if h["severity"] != "info"]
    existing = [h for h in seen.values() if h["severity"] == "info"]

    risk = "low"
    if any(h["severity"] == "critical" for h in exposed):
        risk = "critical"
    elif exposed:
        risk = "high"
    elif existing:
        risk = "medium"

    findings = []
    for h in exposed:
        verb   = "publicly listable" if h["severity"] == "critical" else "publicly accessible"
        src    = f" [{h['source'].upper()}]" if h.get("source") != "probe" else ""
        region = f" ({h['region']})" if h.get("region") else ""
        findings.append(
            f"{h['provider'].upper()} bucket '{h['name']}' is {verb}{src}{region}: {h['url']}"
        )

    return {
        "status":              "ok",
        "candidates_checked":  len(names),
        "endpoints_probed":    len(tasks),
        "s3scanner_used":      _find_s3scanner() is not None,
        "grayhatwarfare_used": bool(GRAYHATWARFARE_KEY),
        "exposed":             exposed,
        "existing_private":    len(existing),
        "existing_private_list": [
            {"name": h["name"], "provider": h["provider"], "url": h.get("url")}
            for h in existing[:200]
        ],
        "exposed_count":       len(exposed),
        "risk":                risk,
        "findings":            findings,
    }


def run(domain: str) -> dict[str, Any]:
    try:
        names          = _candidate_names(domain)
        s3scanner_hits = _run_s3scanner(names)
        return asyncio.run(_run_async(domain, s3scanner_hits))
    except Exception as exc:
        logger.error("cloud_metadata error: %s", exc)
        return {
            "status": "error", "error": str(exc),
            "candidates_checked": 0, "endpoints_probed": 0,
            "s3scanner_used": False, "grayhatwarfare_used": False,
            "exposed": [], "existing_private": 0, "exposed_count": 0,
            "risk": "low", "findings": [],
        }

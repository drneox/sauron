"""
api_exposure.py — Detect publicly exposed API documentation and GraphQL endpoints.

Checks for:
  - OpenAPI / Swagger UI and JSON/YAML specs
  - Redoc, Rapidoc, API Blueprint
  - GraphQL endpoint with introspection enabled
  - gRPC reflection (HTTP/2 grpc.reflection)
  - Off-site public surface: GitHub repos/code mentioning the brand/domain
    (modules.discovery_sources; code search only with GITHUB_TOKEN) and
    Postman Public API Network collections/workspaces

A publicly exposed spec is informational; an unauthenticated GraphQL
introspection is high risk (full schema disclosure).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from modules import discovery_sources
from modules.common import afetch, make_async_client

TIMEOUT     = httpx.Timeout(10.0, connect=6.0)
CONCURRENCY = 10

# (path, label, severity)
_SWAGGER_PATHS: list[tuple[str, str, str]] = [
    # ── Swagger / OpenAPI ───────────────────────────────────────────────────
    ("/swagger.json",              "OpenAPI spec (Swagger JSON)",          "high"),
    ("/swagger.yaml",              "OpenAPI spec (Swagger YAML)",          "high"),
    ("/swagger-ui.html",           "Swagger UI",                           "medium"),
    ("/swagger-ui/index.html",     "Swagger UI",                           "medium"),
    ("/swagger/index.html",        "Swagger UI",                           "medium"),
    ("/swagger/v1/swagger.json",   "OpenAPI spec v1",                      "high"),
    ("/swagger/v2/swagger.json",   "OpenAPI spec v2",                      "high"),
    ("/swagger/v3/swagger.json",   "OpenAPI spec v3",                      "high"),
    ("/openapi.json",              "OpenAPI spec",                         "high"),
    ("/openapi.yaml",              "OpenAPI spec",                         "high"),
    ("/api-docs",                  "API docs",                             "high"),
    ("/api-docs.json",             "API docs JSON",                        "high"),
    ("/api/swagger.json",          "API Swagger spec",                     "high"),
    ("/api/openapi.json",          "API OpenAPI spec",                     "high"),
    ("/api/v1/swagger.json",       "API v1 Swagger spec",                  "high"),
    ("/api/v2/swagger.json",       "API v2 Swagger spec",                  "high"),
    ("/api/v3/swagger.json",       "API v3 Swagger spec",                  "high"),
    ("/v1/api-docs",               "API docs v1",                          "high"),
    ("/v2/api-docs",               "API docs v2",                          "high"),
    ("/v3/api-docs",               "API docs v3",                          "high"),
    ("/api/v1/",                   "API root v1",                          "medium"),
    ("/api/v2/",                   "API root v2",                          "medium"),
    # ── Redoc / Rapidoc ────────────────────────────────────────────────────
    ("/redoc",                     "ReDoc UI",                             "medium"),
    ("/redoc.html",                "ReDoc UI",                             "medium"),
    ("/rapidoc",                   "RapiDoc UI",                           "medium"),
    # ── Spring Boot Actuator (often leaks full API info) ───────────────────
    ("/actuator",                  "Spring Boot Actuator",                 "high"),
    ("/actuator/mappings",         "Spring Actuator – endpoint mappings",  "high"),
    ("/actuator/beans",            "Spring Actuator – bean definitions",   "high"),
    ("/actuator/env",              "Spring Actuator – environment vars",   "critical"),
    ("/actuator/health",           "Spring Actuator – health check",       "medium"),
    # ── Postman / Bruno collections ────────────────────────────────────────
    ("/postman_collection.json",   "Postman collection exposed",           "high"),
]

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/playground",
    "/gql",
    "/query",
]

_GRAPHQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind fields { name } } } }"
})

_OPENAPI_MARKERS = [
    '"swagger":', '"openapi":', "swagger:", "openapi:",
    "Swagger UI", "ReDoc", "RapiDoc",
]

_ACTUATOR_MARKERS = [
    '"status":', '"components":', '"details":', '"beans":', '"mappings":',
]

# Second-level TLDs where the brand sits one label deeper (e.g. example.co.uk)
_SLD_TLDS = {"co", "com", "net", "org", "ac", "gov", "edu"}

# Keywords that mark a Postman collection as exposing internal-looking APIs
_INTERNAL_MARKERS = ("internal", "intranet", "private api", "admin api", "staging")


def _brand_of(domain: str) -> str:
    """Best-effort brand token: 'api.github.com' -> 'github', 'example.co.uk' -> 'example'."""
    labels = [p for p in domain.lower().split(".") if p]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_TLDS:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else domain


async def _probe_swagger(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base_url: str,
    path: str,
    label: str,
    severity: str,
) -> dict | None:
    async with sem:
        url = urljoin(base_url, path)
        try:
            r = await afetch(url, client=client)
            if r.status_code not in (200, 201):
                return None
            body = r.text[:4096]
            ct   = r.headers.get("content-type", "")
            # Must look like an actual API spec, not a login redirect
            if "text/html" in ct and not any(m in body for m in _OPENAPI_MARKERS):
                # Allow actuator HTML if it looks like actuator JSON
                if not any(m in body for m in _ACTUATOR_MARKERS):
                    return None
            return {
                "path":     path,
                "url":      url,
                "label":    label,
                "severity": severity,
                "status":   r.status_code,
                "content_type": ct.split(";")[0].strip(),
            }
        except Exception:
            return None


async def _probe_graphql(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base_url: str,
    path: str,
) -> dict | None:
    async with sem:
        url = urljoin(base_url, path)
        try:
            r = await afetch(
                url,
                client=client,
                method="POST",
                content=_GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
            )
            if r.status_code not in (200, 201):
                return None
            body = r.text
            if '"__schema"' in body or '"queryType"' in body or '"types"' in body:
                # Count exposed types as signal
                type_count = body.count('"name"')
                return {
                    "path":        path,
                    "url":         url,
                    "label":       "GraphQL introspection enabled",
                    "severity":    "high",
                    "status":      r.status_code,
                    "type_count":  type_count,
                    "content_type": r.headers.get("content-type", "").split(";")[0].strip(),
                }
        except Exception:
            pass
    return None


async def _run_async(domain: str) -> dict[str, Any]:
    ssl_ctx = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode    = __import__("ssl").CERT_NONE

    base_https = f"https://{domain}"
    base_http  = f"http://{domain}"

    # Try HTTPS first, fall back to HTTP
    async with make_async_client(
        timeout=httpx.Timeout(5.0, connect=4.0), verify=ssl_ctx,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
    ) as probe:
        try:
            r = await afetch(base_https, client=probe)
            base_url = str(r.url)
        except Exception:
            base_url = base_http

    sem = asyncio.Semaphore(CONCURRENCY)
    async with make_async_client(
        timeout=TIMEOUT, verify=ssl_ctx,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"},
    ) as client:
        swagger_tasks = [
            _probe_swagger(client, sem, base_url, path, label, sev)
            for path, label, sev in _SWAGGER_PATHS
        ]
        graphql_tasks = [
            _probe_graphql(client, sem, base_url, path)
            for path in _GRAPHQL_PATHS
        ]
        brand = _brand_of(domain)
        results, github_repos, github_code_hits, postman = await asyncio.gather(
            asyncio.gather(*swagger_tasks, *graphql_tasks),
            discovery_sources.github_repo_search(brand, domain),
            discovery_sources.github_code_search(domain),
            discovery_sources.postman_search(brand),
        )

    found = [r for r in results if r]

    postman_collections = postman.get("collections") or []
    postman_workspaces  = postman.get("workspaces") or []

    findings = [
        f"{h['label']} accessible at {h['url']} (HTTP {h['status']})"
        for h in found
    ]

    # ── Off-site surface: GitHub + Postman ──────────────────────────────────
    # Extra severities feed the risk calc without touching the `found` shape.
    _order = {"info": 0, "medium": 1, "high": 2, "critical": 3}
    extra_severities: list[str] = []

    for repo in github_repos:
        findings.append(
            f"GitHub repository related to brand '{brand}': {repo['name']} "
            f"({repo['stars']} stars) — {repo['url']}"
        )
        extra_severities.append("info")

    for hit in github_code_hits:
        findings.append(
            f"GitHub code file mentions {domain}: {hit['url']} ({hit['repo']}/{hit['path']})"
        )
        extra_severities.append("info")

    for col in postman_collections:
        text = f"{col['name']} {col.get('description', '')}".lower()
        internal = any(m in text for m in _INTERNAL_MARKERS) or domain.lower() in text
        sev = "medium" if internal else "info"
        tag = " — exposes internal-looking endpoints" if internal else ""
        findings.append(
            f"Postman public collection '{col['name']}' by {col['publisher']}{tag} — {col['url']}"
        )
        extra_severities.append(sev)

    for ws in postman_workspaces:
        findings.append(
            f"Postman public workspace '{ws['name']}' by {ws['publisher']} "
            f"({ws['collections']} collections) — {ws['url']}"
        )
        extra_severities.append("info")

    # Risk = max severity (on-site probes + off-site surface)
    risk = "low"
    severities = [h["severity"] for h in found] + extra_severities
    if severities:
        risk = max(severities, key=lambda s: _order.get(s, 0))

    # Separate graphql from swagger
    swagger_found = [h for h in found if "GraphQL" not in h["label"]]
    graphql_found = [h for h in found if "GraphQL" in h["label"]]

    return {
        "status":          "ok",
        "paths_checked":   len(_SWAGGER_PATHS) + len(_GRAPHQL_PATHS),
        "found":           found,
        "found_count":     len(found),
        "swagger_found":   swagger_found,
        "graphql_found":   graphql_found,
        "has_graphql_introspection": bool(graphql_found),
        "github_repos":       github_repos,
        "github_code_hits":   github_code_hits,
        "postman_collections": postman_collections,
        "postman_workspaces":  postman_workspaces,
        "risk":            risk,
        "findings":        findings,
    }


def run(domain: str) -> dict[str, Any]:
    try:
        return asyncio.run(_run_async(domain))
    except Exception as exc:
        return {
            "status": "error", "error": str(exc),
            "paths_checked": 0, "found": [], "found_count": 0,
            "swagger_found": [], "graphql_found": [],
            "has_graphql_introspection": False,
            "github_repos": [], "github_code_hits": [],
            "postman_collections": [], "postman_workspaces": [],
            "risk": "low", "findings": [],
        }

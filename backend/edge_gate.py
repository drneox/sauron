# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""
Edge gate: network-level protection that runs BEFORE the app login.

Two independent layers, both off by default (dev mode unaffected):

1. IP whitelist — EDGE_ALLOWED_IPS="127.0.0.1,192.168.1.0/24" (csv, CIDR ok).
   Empty/unset = allow all. Non-matching clients get 403 before anything else.
   Behind a reverse proxy the real client IP comes from CF-Connecting-IP,
   honored ONLY when the immediate peer is in EDGE_TRUSTED_PROXIES (default:
   loopback + docker bridge). Raw X-Forwarded-For is never trusted.
2. HTTP Basic auth — EDGE_AUTH_USER + EDGE_AUTH_PASSWORD (requires
   EDGE_AUTH_ENABLED=true). The browser shows its native credentials dialog
   and then sends them automatically on every request (including through the
   Vite proxy, which forwards the Authorization header). A Bearer header
   skips this check only when AUTH_ENABLED=true (the app validates it).

/health stays public for container healthchecks.
"""
import base64
import hmac
import ipaddress
import logging
import os

from fastapi import Response
from starlette.datastructures import Headers

from auth import AUTH_ENABLED

logger = logging.getLogger(__name__)

EDGE_AUTH_ENABLED = os.getenv("EDGE_AUTH_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
EDGE_AUTH_USER = os.getenv("EDGE_AUTH_USER", "")
EDGE_AUTH_PASSWORD = os.getenv("EDGE_AUTH_PASSWORD", "")
# Master switch for honoring CF-Connecting-IP (current prod relies on it:
# cloudflared on the host → nginx → backend). The client's raw
# X-Forwarded-For is NEVER trusted — only CF-Connecting-IP, and only when the
# immediate peer is in EDGE_TRUSTED_PROXIES (nginx rewrites the header from
# its own trusted-peer map before proxying, so by this point a header from a
# trusted peer already carries the real client IP).
EDGE_TRUST_PROXY_HEADERS = os.getenv("EDGE_TRUST_PROXY_HEADERS", "true").strip().lower() in ("1", "true", "yes", "on")

# Peers allowed to supply CF-Connecting-IP: loopback (Vite dev proxy,
# host-side cloudflared) and the docker bridge networks (nginx frontend).
EDGE_TRUSTED_PROXIES = [
    ipaddress.ip_network(item.strip(), strict=False)
    for item in os.getenv("EDGE_TRUSTED_PROXIES", "127.0.0.1,172.16.0.0/12").split(",")
    if item.strip()
]

_ALLOWED_NETWORKS = [
    ipaddress.ip_network(item.strip(), strict=False)
    for item in os.getenv("EDGE_ALLOWED_IPS", "").split(",")
    if item.strip()
]

# Local connections are always allowed (loopback + LAN + link-local).
_LOCAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
              "192.168.0.0/16", "169.254.0.0/16", "fe80::/10")
]

PUBLIC_PATHS = {"/health"}


def _ip_allowed(client_ip: str | None) -> bool:
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    if any(addr in net for net in _LOCAL_NETWORKS):
        return True
    if not _ALLOWED_NETWORKS:
        return True
    return any(addr in net for net in _ALLOWED_NETWORKS)


def _basic_ok(headers: Headers) -> bool:
    auth = headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        user, _, password = decoded.partition(":")
    except Exception:
        return False
    return hmac.compare_digest(user, EDGE_AUTH_USER) and hmac.compare_digest(password, EDGE_AUTH_PASSWORD)


def _trusted_peer(client_ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in net for net in EDGE_TRUSTED_PROXIES)


def _effective_client_ip(peer_ip: str | None, headers: Headers) -> str | None:
    """Client IP used for the whitelist decision.

    CF-Connecting-IP is honored only when the immediate peer is a trusted
    proxy (EDGE_TRUSTED_PROXIES) and the header carries a parseable IP.
    Raw X-Forwarded-For is never consulted: any client can prepend to it.
    """
    if peer_ip and EDGE_TRUST_PROXY_HEADERS and _trusted_peer(peer_ip):
        forwarded = headers.get("cf-connecting-ip")
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded.strip()))
            except ValueError:
                pass
    return peer_ip


class EdgeGateMiddleware:
    """Pure ASGI middleware: IP whitelist → HTTP Basic. Runs inside CORS."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if scope.get("method") == "OPTIONS" or path in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        peer_ip = (scope.get("client") or (None, None))[0]
        client_ip = _effective_client_ip(peer_ip, Headers(scope=scope))
        if not _ip_allowed(client_ip):
            logger.warning(f"[edge] blocked request from {client_ip} (not in EDGE_ALLOWED_IPS)")
            response = Response(status_code=403, content="Forbidden")
            await response(scope, receive, send)
            return

        if EDGE_AUTH_ENABLED and EDGE_AUTH_USER and EDGE_AUTH_PASSWORD:
            headers = Headers(scope=scope)
            auth = headers.get("authorization", "")
            # A Bearer token skips the Basic check only when the app itself
            # validates it (AUTH_ENABLED=true) — with auth disabled a Bearer
            # header must not be a free pass through the edge gate.
            bearer_ok = AUTH_ENABLED and auth.lower().startswith("bearer ")
            if not bearer_ok and not _basic_ok(headers):
                response = Response(
                    status_code=401,
                    content="Authentication required",
                    headers={"WWW-Authenticate": 'Basic realm="Argus"'},
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)

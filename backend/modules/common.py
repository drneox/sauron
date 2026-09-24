"""
Shared HTTP layer for scanner modules.

All outbound HTTP from scan modules should go through here:

- make_client() / make_async_client(): preconfigured httpx clients
  (UA "DumbAuditor/1.0", verify=False, follow_redirects=False). They pick a
  proxy from modules.proxy_pool by default; pass proxy=None explicitly for
  requests that must NEVER go through a proxy (e.g. candidate-key
  verification in secret_verification).

- fetch() / afetch(): GET/HEAD/POST with MANUAL redirect handling (max 5).
  Every hop — including the initial URL — is validated with _is_public_url():
  the host is resolved with socket.getaddrinfo and any private, loopback,
  link-local, reserved, multicast or unspecified address is rejected, as are
  non-http(s) schemes. This blocks SSRF via redirects to cloud metadata
  endpoints (169.254.169.254) or internal networks. The response body is
  streamed and truncated at max_bytes.

A blocked destination raises SSRFBlocked; callers that probe optional URLs
should treat it like a connection error.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from modules import proxy_pool

logger = logging.getLogger(__name__)

USER_AGENT = "DumbAuditor/1.0"
DEFAULT_MAX_BYTES = 2_000_000  # 2 MB
MAX_REDIRECTS = 5

# Sentinel so proxy=None explicitly means "direct connection" while an omitted
# argument means "use the proxy pool if enabled".
_UNSET: Any = object()


class SSRFBlocked(Exception):
    """The URL (or a redirect target) resolves to a non-public address."""


class TooManyRedirects(Exception):
    """Redirect chain exceeded MAX_REDIRECTS."""


def _is_public_url(url: str) -> bool:
    """True if url is http(s) and its host resolves ONLY to public IPs.

    Rejects private/loopback/link-local/reserved/multicast/unspecified
    addresses (e.g. 169.254.169.254, 127.0.0.1, 10.x, 192.168.x, ::1) and
    hosts that fail to resolve.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (ValueError, socket.gaierror, OSError):
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def make_client(proxy: str | None | object = _UNSET, timeout: float = 10, **kw) -> httpx.Client:
    """Preconfigured sync client. Pool proxy by default; proxy=None forces direct."""
    if proxy is _UNSET:
        proxy = proxy_pool.get_proxy()
    if proxy:
        kw["proxy"] = proxy
    headers = {"User-Agent": USER_AGENT} | kw.pop("headers", {})
    return httpx.Client(
        verify=kw.pop("verify", False),
        follow_redirects=False,  # redirects are followed manually by fetch()
        timeout=timeout,
        headers=headers,
        **kw,
    )


def make_async_client(proxy: str | None | object = _UNSET, timeout: float = 10, **kw) -> httpx.AsyncClient:
    """Async twin of make_client()."""
    if proxy is _UNSET:
        proxy = proxy_pool.get_proxy()
    if proxy:
        kw["proxy"] = proxy
    headers = {"User-Agent": USER_AGENT} | kw.pop("headers", {})
    return httpx.AsyncClient(
        verify=kw.pop("verify", False),
        follow_redirects=False,
        timeout=timeout,
        headers=headers,
        **kw,
    )


def is_same_path_redirect(request_url: str, location: str) -> bool:
    """True when a redirect only normalizes the URL (other host, http->https,
    trailing slash) and lands on the very same path.

    Such a redirect says nothing about the probed path existing: a vanity or
    apex domain that 301s everything to its canonical host answers every
    probe this way, real path or not.
    """
    if not location:
        return False
    try:
        target = urlparse(urljoin(request_url, location.strip()))
        probed = urlparse(request_url)
    except ValueError:
        return False
    return (target.path.rstrip("/") == probed.path.rstrip("/")
            and target.query == probed.query)


def _read_limited(resp: httpx.Response, max_bytes: int) -> bytes:
    """Read a streamed response body, truncating at max_bytes."""
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_bytes():
        if total + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - total])
            total = max_bytes
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _materialized_headers(resp: httpx.Response) -> httpx.Headers:
    """Headers for the rebuilt response: the body we attach is already decoded
    and possibly truncated, so hop/encoding/length headers would be lies."""
    drop = {"content-encoding", "content-length", "transfer-encoding"}
    return httpx.Headers({k: v for k, v in resp.headers.items() if k.lower() not in drop})


async def _aread_limited(resp: httpx.Response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        if total + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - total])
            total = max_bytes
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _redirect_request(method: str, status: int, kw: dict) -> tuple[str, dict]:
    """Browser-style redirect semantics: 301/302/303 downgrade a body-carrying
    method to GET; 307/308 preserve it."""
    if status in (301, 302, 303) and method not in ("GET", "HEAD"):
        kw = {k: v for k, v in kw.items() if k not in ("content", "data", "json", "files")}
        return "GET", kw
    return method, kw


def fetch(
    url: str,
    client: httpx.Client | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_redirects: bool = True,
    max_redirects: int = MAX_REDIRECTS,
    method: str = "GET",
    timeout: float = 10,
    **kw,
) -> httpx.Response:
    """Fetch url with per-hop SSRF validation and a hard body-size cap.

    Redirects are followed manually (max 5): each Location target is checked
    with _is_public_url() before the next request. Returns a materialized
    httpx.Response (content already read, truncated at max_bytes) with
    .history populated, so it behaves like a normal follow_redirects=True
    response.
    """
    own = client is None
    if own:
        client = make_client(timeout=timeout)
    try:
        kw.pop("follow_redirects", None)
        current = url
        history: list[httpx.Response] = []
        if not _is_public_url(current):
            logger.warning(f"[common] blocked non-public URL: {current}")
            raise SSRFBlocked(f"blocked non-public URL: {current}")
        for _ in range(max_redirects + 1):
            req = client.build_request(method, current, **kw)
            resp = client.send(req, stream=True, follow_redirects=False)
            try:
                body = _read_limited(resp, max_bytes)
            finally:
                resp.close()
            out = httpx.Response(
                resp.status_code,
                headers=_materialized_headers(resp),
                content=body,
                request=req,
                history=list(history),
            )
            location = out.headers.get("location")
            if allow_redirects and out.is_redirect and location:
                if len(history) >= max_redirects:
                    raise TooManyRedirects(f"too many redirects starting at {url}")
                nxt = urljoin(current, location)
                if not _is_public_url(nxt):
                    logger.warning(f"[common] blocked redirect to non-public URL: {nxt} (from {current})")
                    raise SSRFBlocked(f"blocked redirect to non-public URL: {nxt}")
                history.append(out)
                current = nxt
                method, kw = _redirect_request(method, out.status_code, kw)
                continue
            return out
        raise TooManyRedirects(f"too many redirects starting at {url}")
    finally:
        if own:
            client.close()


async def afetch(
    url: str,
    client: httpx.AsyncClient | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_redirects: bool = True,
    max_redirects: int = MAX_REDIRECTS,
    method: str = "GET",
    timeout: float = 10,
    **kw,
) -> httpx.Response:
    """Async twin of fetch()."""
    own = client is None
    if own:
        client = make_async_client(timeout=timeout)
    try:
        kw.pop("follow_redirects", None)
        current = url
        history: list[httpx.Response] = []
        if not _is_public_url(current):
            logger.warning(f"[common] blocked non-public URL: {current}")
            raise SSRFBlocked(f"blocked non-public URL: {current}")
        for _ in range(max_redirects + 1):
            req = client.build_request(method, current, **kw)
            resp = await client.send(req, stream=True, follow_redirects=False)
            try:
                body = await _aread_limited(resp, max_bytes)
            finally:
                await resp.aclose()
            out = httpx.Response(
                resp.status_code,
                headers=_materialized_headers(resp),
                content=body,
                request=req,
                history=list(history),
            )
            location = out.headers.get("location")
            if allow_redirects and out.is_redirect and location:
                if len(history) >= max_redirects:
                    raise TooManyRedirects(f"too many redirects starting at {url}")
                nxt = urljoin(current, location)
                if not _is_public_url(nxt):
                    logger.warning(f"[common] blocked redirect to non-public URL: {nxt} (from {current})")
                    raise SSRFBlocked(f"blocked redirect to non-public URL: {nxt}")
                history.append(out)
                current = nxt
                method, kw = _redirect_request(method, out.status_code, kw)
                continue
            return out
        raise TooManyRedirects(f"too many redirects starting at {url}")
    finally:
        if own:
            await client.aclose()

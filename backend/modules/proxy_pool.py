"""
Rotating proxy pool for scan egress.

Configuration via environment:
  PROXY_ENABLED=true|false   master switch (default false — everything direct)
  PROXY_FILE=/path/proxies.txt   one proxy per line:
      http://[user:pass@]host:port  or  socks5h://[user:pass@]host:port
      (blank lines and # comments ignored)
  PROXY_GATEWAY=http://host:port   single rotating gateway; combined with
      PROXY_FILE entries if both are set.

At load time every proxy is health-checked (HEAD https://example.com,
5s timeout); only live proxies enter the pool. get_proxy() round-robins
between live entries and returns None when the feature is disabled or no
proxy is alive, so callers degrade to direct connections transparently.
mark_dead() removes a proxy after a failure.

Note: socks5h:// proxies require the optional socksio package (httpx[socks]);
without it they are skipped at load time with a warning.

GOLDEN RULE: any request carrying candidate secrets (secret_verification)
must use proxy=None — key material never leaves through a third-party proxy.
"""
from __future__ import annotations

import logging
import os
import threading

import httpx

logger = logging.getLogger(__name__)

HEALTHCHECK_URL = "https://example.com"
HEALTHCHECK_TIMEOUT = 5
IPIFY_URL = "https://api.ipify.org"

_lock = threading.Lock()
_loaded = False
_proxies: list[str] = []   # configured entries, in file order (gateway last)
_dead: set[str] = set()
_rr_index = 0


def enabled() -> bool:
    return os.getenv("PROXY_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


def _socks_supported() -> bool:
    try:
        import socksio  # noqa: F401
        return True
    except ImportError:
        return False


def _configured_proxies() -> list[str]:
    proxies: list[str] = []
    proxy_file = os.getenv("PROXY_FILE", "").strip()
    if proxy_file:
        try:
            with open(proxy_file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxies.append(line)
        except OSError as e:
            logger.error(f"[proxy_pool] cannot read PROXY_FILE {proxy_file}: {e}")
    gateway = os.getenv("PROXY_GATEWAY", "").strip()
    if gateway:
        proxies.append(gateway)
    if not _socks_supported():
        http_only = [p for p in proxies if not p.startswith("socks")]
        skipped = len(proxies) - len(http_only)
        if skipped:
            logger.warning(f"[proxy_pool] {skipped} socks proxy(ies) skipped — socksio not installed (httpx[socks])")
        proxies = http_only
    return proxies


def _check_alive(proxy: str) -> bool:
    try:
        with httpx.Client(proxy=proxy, timeout=HEALTHCHECK_TIMEOUT, verify=False) as c:
            r = c.head(HEALTHCHECK_URL)
            return r.status_code < 500
    except Exception as e:
        logger.info(f"[proxy_pool] proxy dead: {proxy} ({type(e).__name__})")
        return False


def _load_locked() -> None:
    """(Re)load the pool. Caller must hold _lock."""
    global _loaded, _rr_index
    _loaded = True
    _rr_index = 0
    _dead.clear()
    _proxies[:] = _configured_proxies()
    if not _proxies:
        return
    alive = 0
    for p in _proxies:
        if _check_alive(p):
            alive += 1
        else:
            _dead.add(p)
    logger.info(f"[proxy_pool] loaded {len(_proxies)} proxy(ies), {alive} alive")


def _ensure_loaded() -> None:
    global _loaded
    if not _loaded:
        _load_locked()


def reload() -> None:
    """Force re-read of env config and re-run health checks."""
    global _loaded
    with _lock:
        _loaded = False
        _ensure_loaded()


def get_proxy() -> str | None:
    """Next live proxy (round-robin), or None if disabled / none alive."""
    if not enabled():
        return None
    with _lock:
        _ensure_loaded()
        global _rr_index
        alive = [p for p in _proxies if p not in _dead]
        if not alive:
            return None
        proxy = alive[_rr_index % len(alive)]
        _rr_index += 1
        return proxy


def mark_dead(proxy: str | None) -> None:
    """Remove a proxy from rotation after a failure."""
    if not proxy:
        return
    with _lock:
        _dead.add(proxy)
    logger.info(f"[proxy_pool] marked dead: {proxy}")


def pool_status() -> dict:
    with _lock:
        _ensure_loaded()
        return {
            "enabled": enabled(),
            "configured": list(_proxies),
            "alive": [p for p in _proxies if p not in _dead],
        }


def current_egress_ip() -> str | None:
    """Public egress IP seen through the current proxy (for audit logging).
    Returns None if disabled, no live proxy, or the lookup fails."""
    proxy = get_proxy()
    if not proxy:
        return None
    try:
        with httpx.Client(proxy=proxy, timeout=HEALTHCHECK_TIMEOUT, verify=False) as c:
            r = c.get(IPIFY_URL)
            if r.status_code == 200:
                return r.text.strip()
    except Exception as e:
        logger.info(f"[proxy_pool] egress IP lookup failed via {proxy}: {type(e).__name__}")
    return None

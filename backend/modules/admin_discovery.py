"""
Admin Panel Discovery Module
Probes common admin/login/management paths with strict false-positive reduction.

Validation strategy per HTTP status:
  200  -> Only report if the body contains login/admin content signals AND
          body hash does not match the homepage or soft-404 baseline.
  401  -> Always report: the server is actively protecting this resource.
  403  -> Informational only ("restricted"): blocked/forbidden, not exposed.
  301/302 -> Informational only: redirects (even to login-looking paths) are not
             proof of an exposed panel (trailing-slash normalization, SPA
             catch-alls, etc.).
"""
import hashlib
import httpx
import asyncio
import logging
import re
from typing import Any

from modules.common import afetch, fetch, make_async_client

logger = logging.getLogger(__name__)

TIMEOUT     = 8
CONCURRENCY = 20

ADMIN_PATHS = [
    # Generic admin panels
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin/login", "/admin/login.php", "/admin/index.php",
    "/admin/dashboard", "/adminpanel", "/adminarea",
    "/backend", "/backend/", "/manage", "/management",
    "/controlpanel", "/panel", "/portal",
    # CMS backends
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin", "/phpmyadmin/", "/pma",
    "/typo3", "/typo3/", "/craft/admin", "/ghost/admin",
    "/umbraco", "/umbraco/",
    "/sitecore", "/kentico",
    "/joomla/administrator", "/magento/admin",
    "/prestashop/admin", "/opencart/admin",
    # Auth / login pages
    "/login", "/login/", "/signin", "/sign-in",
    "/auth/login", "/auth/signin",
    "/account/login", "/user/login", "/users/login",
    "/session/new",
    # API dev tools
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html",
    "/swagger/index.html", "/api-docs", "/api-docs/",
    "/openapi.json", "/graphql", "/graphiql",
    # Spring Boot Actuator
    "/actuator", "/actuator/", "/actuator/env", "/actuator/beans",
    "/actuator/health", "/actuator/info", "/actuator/mappings",
    # Monitoring / DevOps UIs
    "/kibana", "/kibana/", "/grafana", "/grafana/",
    "/prometheus", "/jenkins", "/jenkins/",
    "/portainer", "/portainer/",
    # Debug / dev endpoints
    "/console", "/dev", "/debug",
    "/server-status", "/server-info",
]

# These paths should never be public — 403 alone (with unique body) is enough
ALWAYS_REPORT_403 = {
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
}

# Content signals confirming a 200 is a real admin/login page
_LOGIN_SIGNALS: list[bytes] = [
    b'type="password"', b"type='password'", b"type=password",
    b'name="password"', b"name='password'",
    b"<form", b"<FORM",
    b"log in", b"login", b"Log In", b"Login",
    b"sign in", b"Sign In", b"signin",
    b"username", b"Username",
    b"admin panel", b"Admin Panel", b"dashboard", b"Dashboard",
    b"phpMyAdmin", b"phpmyadmin",
    b"WordPress", b"Joomla", b"Drupal", b"Magento",
    b"grafana", b"Grafana", b"Kibana", b"Jenkins",
    b"Portainer", b"swagger", b"GraphQL", b"GraphiQL",
    b"actuator", b"Spring Boot",
]

_LOGIN_REDIRECT_RE = re.compile(
    r"/(login|signin|sign-in|auth|admin|wp-admin|wp-login|dashboard|portal|console)",
    re.IGNORECASE,
)


def _body_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def _has_login_signal(body: bytes) -> bool:
    body_lower = body.lower()
    return any(sig.lower() in body_lower for sig in _LOGIN_SIGNALS)


def _redirect_looks_real(location: str, base_url: str) -> bool:
    if not location:
        return False
    loc = location.strip().rstrip("/")
    if loc in ("", "/", base_url.rstrip("/")):
        return False
    if loc.rstrip("/") == base_url.rstrip("/"):
        return False
    return bool(_LOGIN_REDIRECT_RE.search(loc))


async def _calibrate(client: httpx.AsyncClient, base_url: str) -> dict:
    homepage_hash   = None
    soft404_hashes: set[str] = set()

    try:
        r = await afetch(base_url + "/", client=client, timeout=6)
        homepage_hash = _body_hash(r.content)
    except Exception:
        pass

    for path in ("/a1b2c3_notarealadminpath_xyz", "/zz_fake_login_9182736_test", "/admin_does_not_exist_55a4b3"):
        try:
            r = await afetch(base_url + path, client=client, allow_redirects=False, timeout=5)
            soft404_hashes.add(_body_hash(r.content))
        except Exception:
            pass

    return {"homepage_hash": homepage_hash, "soft404_hashes": soft404_hashes}


def _severity(path: str, status: int) -> str:
    p = path.lower()
    if "/actuator/" in p or p in ("/actuator", "/actuator/"):
        return "critical"
    high_pat = ("/phpmyadmin", "/pma", "/admin", "/administrator", "/wp-admin",
                "/wp-login", "/graphiql", "/swagger", "/console", "/debug",
                "/jenkins", "/portainer", "/grafana", "/kibana")
    if any(h in p for h in high_pat):
        return "high" if status in (200, 401) else "medium"
    return "high" if status == 401 else "medium"


async def _probe(client: httpx.AsyncClient, base_url: str, path: str, baseline: dict) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        r = await afetch(url, client=client, allow_redirects=False, timeout=TIMEOUT)
    except Exception:
        return None

    status = r.status_code
    body   = r.content
    bh     = _body_hash(body)
    ct     = r.headers.get("content-type", "").split(";")[0].strip().lower()

    # 401 — server is actively protecting this resource
    if status == 401:
        return {"path": path, "url": url, "status": status,
                "severity": _severity(path, status), "content_type": ct,
                "size": len(body), "redirect_to": None}

    # 403 — only if body is unique (not WAF catchall)
    if status == 403:
        if bh in baseline["soft404_hashes"]:
            return None
        if baseline["homepage_hash"] and bh == baseline["homepage_hash"]:
            return None
        if path in ALWAYS_REPORT_403:
            return {"path": path, "url": url, "status": status,
                    "severity": _severity(path, status), "content_type": ct,
                    "size": len(body), "redirect_to": None}
        # 403 = blocked/forbidden, not an exposed panel — informational only,
        # kept out of `found` so it never shows up as a positive admin panel
        return {"path": path, "url": url, "status": status,
                "severity": "info", "content_type": ct,
                "size": len(body), "redirect_to": None, "restricted": True}

    # 301/302 — redirects are not proof of an exposed panel; informational only
    if status in (301, 302):
        location = r.headers.get("location", "")
        if not _redirect_looks_real(location, base_url):
            return None
        return {"path": path, "url": url, "status": status,
                "severity": "info", "content_type": ct,
                "size": len(body), "redirect_to": location, "restricted": True}

    # 200 — only if body has real login/admin content signals
    if status == 200:
        if baseline["homepage_hash"] and bh == baseline["homepage_hash"]:
            return None
        if bh in baseline["soft404_hashes"]:
            return None
        if b"404" in body[:2000] and b"not found" in body[:2000].lower():
            return None
        if not _has_login_signal(body):
            return None
        return {"path": path, "url": url, "status": status,
                "severity": _severity(path, status), "content_type": ct,
                "size": len(body), "redirect_to": None}

    return None


async def _run_async(base_url: str) -> tuple[list[dict], list[dict]]:
    sem = asyncio.Semaphore(CONCURRENCY)
    async with make_async_client(
        timeout=TIMEOUT,
        headers={"User-Agent": "Mozilla/5.0 (compatible; DumbAuditor/1.0)"},
    ) as client:
        baseline = await _calibrate(client, base_url)

        async def bounded(path: str):
            async with sem:
                return await _probe(client, base_url, path, baseline)

        results = await asyncio.gather(*[bounded(p) for p in ADMIN_PATHS], return_exceptions=True)

    found = [r for r in results if isinstance(r, dict)]

    # Deduplicate trailing-slash variants
    seen: set[str] = set()
    deduped = []
    for item in found:
        key = item["path"].rstrip("/")
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    deduped.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "info": 3}.get(x["severity"], 99))
    found      = [i for i in deduped if not i.get("restricted")]
    restricted = [i for i in deduped if i.get("restricted")]
    return found, restricted


def run(domain: str) -> dict[str, Any]:
    findings: list[str] = []
    risk = "low"

    base_url = f"https://{domain}"
    try:
        test = fetch(base_url, method="HEAD", timeout=5, allow_redirects=False)
        if test.status_code >= 500:
            base_url = f"http://{domain}"
    except Exception:
        base_url = f"http://{domain}"

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            found, restricted = loop.run_until_complete(_run_async(base_url))
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"admin_discovery error: {e}")
        found, restricted = [], []

    critical = [f for f in found if f["severity"] == "critical"]
    high     = [f for f in found if f["severity"] == "high"]
    medium   = [f for f in found if f["severity"] == "medium"]

    if critical:
        risk = "critical"
        findings.append(f"{len(critical)} critical management endpoint(s) exposed: " + ", ".join(f["path"] for f in critical))
    if high:
        risk = risk if risk == "critical" else "high"
        findings.append(f"{len(high)} admin panel(s) confirmed: " + ", ".join(f["path"] for f in high[:5]))
    if medium:
        risk = risk if risk in ("critical", "high") else "medium"
        findings.append(f"{len(medium)} path(s) redirecting to auth/admin endpoints")
    if restricted:
        findings.append(f"{len(restricted)} path(s) blocked with 403 (protected/forbidden, not exposed): " + ", ".join(f["path"] for f in restricted[:5]))

    return {
        "status":           "ok",
        "paths_probed":     len(ADMIN_PATHS),
        "found":            found,
        "found_count":      len(found),
        "restricted":       restricted,
        "restricted_count": len(restricted),
        "critical_count":   len(critical),
        "high_count":       len(high),
        "risk":             risk,
        "findings":         findings,
    }

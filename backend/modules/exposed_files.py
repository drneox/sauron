"""
Exposed Files & Sensitive Paths Module
Probes for accidentally exposed files, backups, admin panels,
configuration files, version control, and cloud metadata endpoints.

False-positive reduction techniques:
  1. Baseline calibration — probe random non-existent paths first.
     If the server returns 403/200 for garbage paths, those codes are
     unreliable and we adjust our confidence accordingly.
  2. Body-hash fingerprinting — compare each 403/200 response body hash
     against the baseline body. Matching hash → WAF wall, not a real file.
  3. Content validation — for file types with known signatures
     (.git/HEAD must contain "ref:", .env must contain KEY=VALUE, etc.)
     we verify the body looks authentic before reporting.
  4. 403-bypass probing — for high/critical candidates returning 403,
     try path-normalization bypasses (/path/ //path /./path unicode).
     A bypass that returns 200 with real content confirms the resource.
  5. Size consistency gate — if ≥ 2 distinct paths all return 403 with
     the same body size, that size is flagged as a "wall size" and further
     403s matching it are suppressed.
"""
import hashlib
import httpx
import asyncio
import logging
import random
import string
from typing import Any

from modules.common import afetch, make_async_client

logger = logging.getLogger(__name__)

# Magic byte signatures for binary file formats.
# A 200 response that doesn't start with these bytes can't be the real file.
_MAGIC: dict[str, bytes | list[bytes]] = {
    ".zip":    [b"PK\x03\x04", b"PK\x05\x06"],
    ".tar":    b"ustar",          # may appear at offset 257
    ".gz":     b"\x1f\x8b",
    ".7z":     b"7z\xbc\xaf'\x1c",
    ".sqlite": b"SQLite format 3",
    ".sqlite3": b"SQLite format 3",
    ".sql":    None,              # text, use content validation
    ".pdf":    b"%PDF",
}

# (path, description, severity)
SENSITIVE_PATHS = [
    # ── Version control ───────────────────────────────────────────────────────
    ("/.git/HEAD",              "Git repository exposed",              "critical"),
    ("/.git/config",            "Git config exposed",                  "critical"),
    ("/.git/COMMIT_EDITMSG",    "Git commit message exposed",          "high"),
    ("/.git/logs/HEAD",         "Git log exposed",                     "high"),
    ("/.svn/entries",           "SVN repository exposed",              "critical"),
    ("/.svn/wc.db",             "SVN working copy DB exposed",         "critical"),
    ("/.hg/hgrc",               "Mercurial repo exposed",              "high"),

    # ── Environment & config ──────────────────────────────────────────────────
    ("/.env",                   ".env file (credentials)",             "critical"),
    ("/.env.local",             ".env.local exposed",                  "critical"),
    ("/.env.production",        ".env.production exposed",             "critical"),
    ("/.env.staging",           ".env.staging exposed",                "critical"),
    ("/.env.backup",            ".env.backup exposed",                 "critical"),
    ("/.env.bak",               ".env.bak exposed",                    "critical"),
    ("/config.php",             "PHP config exposed",                  "critical"),
    ("/config.yml",             "YAML config exposed",                 "high"),
    ("/config.yaml",            "YAML config exposed",                 "high"),
    ("/config.json",            "JSON config exposed",                 "high"),
    ("/settings.py",            "Python settings exposed",             "high"),
    ("/wp-config.php",          "WordPress config exposed",            "critical"),
    ("/wp-config.php.bak",      "WordPress config backup",             "critical"),
    ("/configuration.php",      "Joomla config exposed",               "critical"),
    ("/app/etc/local.xml",      "Magento config exposed",              "critical"),
    ("/.htaccess",              ".htaccess exposed",                   "medium"),
    ("/web.config",             "web.config exposed",                  "high"),
    ("/appsettings.json",       "ASP.NET appsettings exposed",         "high"),
    ("/secrets.json",           "secrets.json exposed",                "critical"),
    ("/credentials.json",       "credentials.json exposed",            "critical"),
    ("/database.yml",           "Database credentials (Rails)",        "critical"),

    # ── Backups ───────────────────────────────────────────────────────────────
    ("/backup.zip",             "Backup archive exposed",              "critical"),
    ("/backup.tar.gz",          "Backup archive exposed",              "critical"),
    ("/backup.sql",             "SQL backup exposed",                  "critical"),
    ("/dump.sql",               "SQL dump exposed",                    "critical"),
    ("/database.sql",           "Database dump exposed",               "critical"),
    ("/db.sql",                 "Database dump exposed",               "critical"),
    ("/db.sqlite",              "SQLite database exposed",             "critical"),
    ("/db.sqlite3",             "SQLite3 database exposed",            "critical"),
    ("/backup.7z",              "Backup archive exposed",              "critical"),
    ("/site.zip",               "Site backup exposed",                 "critical"),
    ("/www.zip",                "Site backup exposed",                 "critical"),

    # ── Logs & debug ──────────────────────────────────────────────────────────
    ("/debug",                  "Debug endpoint exposed",              "high"),
    ("/logs",                   "Logs directory exposed",              "high"),
    ("/error.log",              "Error log exposed",                   "high"),
    ("/access.log",             "Access log exposed",                  "high"),
    ("/server.log",             "Server log exposed",                  "high"),
    ("/debug.log",              "Debug log exposed",                   "high"),
    ("/phpinfo.php",            "phpinfo() exposed",                   "high"),
    ("/info.php",               "phpinfo() exposed",                   "high"),
    ("/test.php",               "test.php exposed",                    "medium"),

    # ── Admin panels ─────────────────────────────────────────────────────────
    ("/phpmyadmin",             "phpMyAdmin exposed",                  "critical"),
    ("/phpmyadmin/",            "phpMyAdmin exposed",                  "critical"),
    ("/pma",                    "phpMyAdmin (pma) exposed",            "critical"),
    ("/wp-admin/",              "WordPress admin exposed",             "medium"),
    ("/wp-login.php",           "WordPress login exposed",             "medium"),
    ("/adminer.php",            "Adminer DB exposed",                  "critical"),
    ("/adminer",                "Adminer DB exposed",                  "critical"),

    # ── API & docs ────────────────────────────────────────────────────────────
    ("/swagger.json",           "Swagger JSON spec exposed",           "medium"),
    ("/swagger.yaml",           "Swagger YAML spec exposed",           "medium"),
    ("/openapi.json",           "OpenAPI spec exposed",                "medium"),
    ("/openapi.yaml",           "OpenAPI YAML spec exposed",           "medium"),
    ("/swagger-ui.html",        "Swagger UI exposed",                  "medium"),
    ("/api-docs",               "API docs exposed",                    "medium"),
    ("/graphql",                "GraphQL endpoint exposed",            "medium"),

    # ── Cloud / infrastructure ────────────────────────────────────────────────
    ("/latest/meta-data/",      "AWS EC2 metadata proxy exposed",      "critical"),
    ("/metadata/v1",            "DigitalOcean metadata proxy exposed", "critical"),
    ("/Dockerfile",             "Dockerfile exposed",                  "medium"),
    ("/docker-compose.yml",     "docker-compose.yml exposed",         "high"),
    ("/docker-compose.yaml",    "docker-compose.yaml exposed",        "high"),
    ("/terraform.tfvars",       "Terraform vars exposed",              "critical"),
    ("/terraform.tfstate",      "Terraform state exposed",             "critical"),
    ("/.travis.yml",            ".travis.yml exposed",                 "medium"),
    ("/.circleci/config.yml",   "CircleCI config exposed",             "medium"),

    # ── Misc sensitive ────────────────────────────────────────────────────────
    ("/crossdomain.xml",        "crossdomain.xml exposed",             "medium"),
    ("/server-status",          "Apache server-status exposed",        "high"),
    ("/server-info",            "Apache server-info exposed",          "high"),
    ("/_profiler",              "Symfony profiler exposed",            "high"),
    ("/.DS_Store",              ".DS_Store (file list leak)",          "medium"),
    ("/package.json",           "package.json exposed (deps)",         "medium"),
    ("/composer.json",          "composer.json exposed",               "medium"),
    ("/yarn.lock",              "yarn.lock exposed",                   "low"),
    ("/Makefile",               "Makefile exposed",                    "low"),
    ("/.well-known/security.txt", "security.txt (positive)",          "info"),
    ("/robots.txt",             "robots.txt (info disclosure)",        "info"),
    ("/sitemap.xml",            "sitemap.xml (info disclosure)",       "info"),
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Paths where a 403 is almost certainly a real access-control response
# (specific enough that a WAF wouldn't return 403 speculatively for them
# unless the resource actually exists at the OS level)
TRUSTED_403_PATHS = {
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/logs/HEAD",
    "/.svn/entries", "/.svn/wc.db",
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.backup", "/.env.bak",
    "/wp-config.php", "/wp-config.php.bak",
    "/adminer.php",
    "/terraform.tfvars", "/terraform.tfstate",
    "/phpmyadmin", "/phpmyadmin/",
}

# Expected content signatures for response-body validation.
# A 200 response that doesn't contain any of these strings is probably a soft-404.
CONTENT_SIGNATURES: dict[str, list[str]] = {
    "/.git/HEAD":           ["ref:", "refs/heads/"],
    "/.git/config":         ["[core]", "[remote", "[branch"],
    "/.git/COMMIT_EDITMSG": ["merge", "fix", "feat", "update", "add", "initial", "bump"],
    "/.svn/entries":        ["<?xml", "dir", "svn:"],
    "/.env":                ["="],
    "/.env.local":          ["="],
    "/.env.production":     ["="],
    "/.env.staging":        ["="],
    "/.env.backup":         ["="],
    "/.env.bak":            ["="],
    "/wp-config.php":       ["DB_NAME", "DB_USER", "table_prefix", "define("],
    "/config.php":          ["$db", "$config", "define(", "<?php"],
    "/configuration.php":   ["<?php", "joomla", "JConfig", "$config"],
    "/phpinfo.php":         ["phpinfo", "PHP Version", "php.ini"],
    "/info.php":            ["phpinfo", "PHP Version"],
    "/terraform.tfstate":   ['"version"', '"terraform_version"', '"resources"'],
    "/terraform.tfvars":    ["="],
    "/docker-compose.yml":  ["version:", "services:", "image:"],
    "/docker-compose.yaml": ["version:", "services:", "image:"],
    "/package.json":        ['"name"', '"version"', '"dependencies"', '"scripts"'],
    "/composer.json":       ['"name"', '"require"', '"autoload"'],
    "/appsettings.json":    ['"ConnectionStrings"', '"Logging"', '"AllowedHosts"', '"AppSettings"'],
    "/config.json":         ['{'],        # any JSON is better than HTML
    "/secrets.json":        ['{'],
    "/credentials.json":    ['{'],
    "/config.yml":          [': '],        # YAML key: value
    "/config.yaml":         [': '],
    "/database.yml":        ['adapter:', 'database:', 'username:'],
    "/settings.py":         ['DEBUG', 'DATABASES', 'SECRET_KEY', 'INSTALLED_APPS'],
    "/web.config":          ['<?xml', '<configuration', '<system.web'],
    "/adminer.php":         ["adminer", "login", "select", "Adminer"],
    "/server-status":       ["Apache", "requests", "Server Version", "uptime"],
    "/swagger.json":        ['"swagger"', '"openapi"', '"paths"'],
    "/swagger.yaml":        ["swagger:", "openapi:", "paths:"],
    "/openapi.json":        ['"openapi"', '"paths"'],
    "/openapi.yaml":        ["openapi:", "paths:"],
    "/backup.sql":          ["INSERT", "CREATE TABLE", "--", "LOCK TABLES"],
    "/dump.sql":            ["INSERT", "CREATE TABLE", "--", "LOCK TABLES"],
    "/database.sql":        ["INSERT", "CREATE TABLE", "--", "LOCK TABLES"],
    "/db.sql":              ["INSERT", "CREATE TABLE", "--", "LOCK TABLES"],
    "/error.log":           ["error", "warning", "exception", "stack", "fatal"],
    "/access.log":          ["GET /", "POST /", "HTTP/", "200", "404"],
    "/debug.log":           ["debug", "error", "info", "warning"],
    "/server.log":          ["started", "error", "listening", "connection"],
    "/.travis.yml":         ["language:", "script:", "branches:"],
    "/.circleci/config.yml":["version:", "jobs:", "workflows:"],
    "/crossdomain.xml":     ["<?xml", "cross-domain-policy", "allow-access-from"],
    "/Dockerfile":          ["FROM ", "RUN ", "CMD ", "EXPOSE ", "WORKDIR "],
    "/.htaccess":           ["RewriteEngine", "Allow", "Deny", "Options", "AuthType"],
}

# Extensions that should NEVER be served as text/html if they are real files.
# A text/html Content-Type for these paths almost always means a catch-all/404 page.
_NON_HTML_EXTENSIONS = frozenset([
    ".env", ".sql", ".sqlite", ".sqlite3", ".zip", ".tar", ".gz", ".7z",
    ".yml", ".yaml", ".json", ".php", ".py", ".log", ".bak", ".xml",
    ".config", ".conf", ".htaccess",
])
_NON_HTML_PATHS = frozenset([
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/logs/HEAD",
    "/.svn/entries", "/.svn/wc.db",
    "/Dockerfile", "/Makefile",
])

# WAF / CDN response headers that indicate a platform-level 403 block
_WAF_HEADERS = frozenset([
    "cf-ray", "cf-cache-status",       # Cloudflare
    "x-amzn-requestid", "x-amz-cf-id", # AWS CloudFront / API GW
    "x-akamai-request-id",             # Akamai
    "x-sucuri-id", "x-sucuri-cache",   # Sucuri
    "x-fw-hash",                       # Fastly WAF
    "x-iinfo",                         # Imperva
    "x-cdn",                           # Generic CDN
])


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _body_hash(body: bytes) -> str:
    return hashlib.md5(body[:4096]).hexdigest()


def _body_hash_full(body: bytes) -> str:
    """Full-body hash for homepage fingerprinting."""
    return hashlib.md5(body).hexdigest()


def _similar_size(a: int, b: int, tolerance: float = 0.05) -> bool:
    """True if sizes differ by less than `tolerance` fraction."""
    if a == 0 and b == 0:
        return True
    return abs(a - b) / max(a, b) < tolerance


def _check_magic(path: str, body: bytes) -> bool:
    """
    For known binary formats, verify the response starts with the
    expected magic bytes. Returns True if check passes (or not applicable).
    """
    import os
    ext = os.path.splitext(path)[1].lower()
    magic = _MAGIC.get(ext)
    if magic is None:
        return True  # no magic defined for this extension
    if isinstance(magic, list):
        return any(body.startswith(m) for m in magic)
    # .tar: magic at fixed offset 257
    if ext == ".tar":
        return magic in body[250:270]
    return body.startswith(magic)


def _random_path() -> str:
    rand = "".join(random.choices(string.ascii_lowercase, k=14))
    return f"/{rand}"


def _has_waf_header(headers: httpx.Headers) -> bool:
    return any(h in headers for h in _WAF_HEADERS)


# WAF block pages embed unique tokens (e.g. Cloudflare Ray ID), so their body
# hash never matches the baseline — content markers are the reliable signal.
_BLOCK_PAGE_MARKERS = (
    b"you have been blocked",
    b"cloudflare ray id",
    b"sucuri website firewall",
    b"incapsula incident id",
    b"request blocked by",
)


def _is_waf_block_page(body: bytes) -> bool:
    head = body[:8192].lower()
    return any(m in head for m in _BLOCK_PAGE_MARKERS)


def _content_validates(path: str, body_text: str) -> bool:
    """Return True if the body matches expected file content, or no signature defined."""
    sigs = CONTENT_SIGNATURES.get(path)
    if not sigs:
        return True
    return any(sig.lower() in body_text.lower() for sig in sigs)


def _is_html_response(content_type: str) -> bool:
    return "text/html" in content_type.lower()


def _should_reject_html(path: str) -> bool:
    """True if this path should NEVER return text/html when it's a real file."""
    import os
    if path in _NON_HTML_PATHS:
        return True
    ext = os.path.splitext(path)[1].lower()
    return ext in _NON_HTML_EXTENSIONS


def _downgrade(severity: str) -> str:
    """Drop severity one notch to reflect reduced confidence."""
    order = ["info", "low", "medium", "high", "critical"]
    idx = order.index(severity) if severity in order else 2
    return order[max(0, idx - 1)]


def _bypass_variants(path: str) -> list[str]:
    """
    Path-normalization bypass candidates used by ffuf/feroxbuster.
    If any variant returns 200 with valid content, the resource is confirmed.
    """
    p = path.rstrip("/")
    variants = [
        p + "/",
        "//" + p.lstrip("/"),
        p + "/.",
        p + ";/",
        p + "%20",
        p + "?",
    ]
    return [v for v in variants if v != path]


# ─── Baseline calibration ─────────────────────────────────────────────────────

async def _get_baseline(client: httpx.AsyncClient, base_url: str) -> dict:
    """
    Send 5 requests to random non-existent paths and record:
    - Which status codes the server returns for missing paths
    - Body hashes and sizes of those responses
    - Where a redirect wall bounces missing paths to (e.g. every unknown
      path -> /login), so a real prober can tell "exists but gated" apart
      from "doesn't exist, just redirected like everything else"
    Also fetches the homepage (/) to detect catch-all SPA servers.
    Returns a fingerprint dict used later to filter false positives.
    """
    from collections import Counter
    hashes_403: set[str] = set()       # MD5 of first 4096 bytes
    hashes_200: set[str] = set()
    full_hashes_200: set[str] = set()  # full-body MD5
    sizes_403: Counter  = Counter()
    sizes_200: list[int] = []
    redirect_locations: Counter = Counter()
    returns_403 = False
    returns_200 = False
    returns_redirect = False
    waf_on_baseline = False
    waf_blocked = False

    # Probe random non-existent paths (mix: plain + with extensions)
    probes = [
        _random_path(),
        _random_path(),
        _random_path() + ".html",
        _random_path() + ".php",
        _random_path(),
    ]
    for probe in probes:
        url = base_url + probe
        try:
            resp = await afetch(url, client=client, allow_redirects=False)
            h = _body_hash(resp.content)
            if resp.status_code == 403:
                hashes_403.add(h)
                sizes_403[len(resp.content)] += 1
                returns_403 = True
                if _has_waf_header(resp.headers):
                    waf_on_baseline = True
                if _is_waf_block_page(resp.content):
                    waf_blocked = True
            elif resp.status_code == 200:
                hashes_200.add(h)
                full_hashes_200.add(_body_hash_full(resp.content))
                sizes_200.append(len(resp.content))
                returns_200 = True
            elif resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "").rstrip("/")
                if loc:
                    redirect_locations[loc] += 1
                    returns_redirect = True
        except Exception:
            pass

    # Also fingerprint the homepage to catch SPA catch-all servers
    homepage_hash: str | None = None
    homepage_full_hash: str | None = None
    homepage_size: int | None = None
    try:
        r = await afetch(base_url + "/", client=client)
        if r.status_code == 200 and len(r.content) > 200:
            homepage_hash = _body_hash(r.content)
            homepage_full_hash = _body_hash_full(r.content)
            homepage_size = len(r.content)
            # If the homepage itself shows up in our random 404 probes it's a catch-all
            if homepage_hash in hashes_200:
                returns_200 = True  # already set
    except Exception:
        pass

    # Identify a "wall size": a 403 body size that appeared ≥2 times
    wall_size: int | None = None
    for size, count in sizes_403.items():
        if count >= 2:
            wall_size = size
            break

    # Identify a "redirect wall": a redirect target that random non-existent
    # paths hit ≥2 times — e.g. everything unauthenticated bounces to /login.
    # Any probe that redirects to this same target is noise, not a hit.
    redirect_wall_target: str | None = None
    for loc, count in redirect_locations.items():
        if count >= 2:
            redirect_wall_target = loc
            break

    # Median 200 size (for soft-404 size comparison)
    median_200: int | None = None
    if sizes_200:
        sizes_200.sort()
        median_200 = sizes_200[len(sizes_200) // 2]

    return {
        "hashes_403":       hashes_403,
        "hashes_200":       hashes_200,
        "full_hashes_200":  full_hashes_200,
        "wall_size":        wall_size,
        "median_200":       median_200,
        "returns_403":      returns_403,
        "returns_200":      returns_200,
        "returns_redirect": returns_redirect,
        "redirect_wall_target": redirect_wall_target,
        "waf_on_baseline":  waf_on_baseline,
        "waf_blocked":      waf_blocked,
        "homepage_hash":    homepage_hash,
        "homepage_full_hash": homepage_full_hash,
        "homepage_size":    homepage_size,
    }


# ─── Probe ────────────────────────────────────────────────────────────────────

async def _probe(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    description: str,
    severity: str,
    semaphore: asyncio.Semaphore,
    baseline: dict,
) -> dict | None:
    async with semaphore:
        url = base_url.rstrip("/") + path
        try:
            resp = await afetch(url, client=client, allow_redirects=False)
        except (httpx.ConnectError, httpx.TimeoutException):
            return None
        except Exception as e:
            logger.debug(f"[exposed] {url}: {e}")
            return None

        code = resp.status_code
        body = resp.content
        body_text = body.decode("utf-8", errors="replace")
        content_type = resp.headers.get("content-type", "")
        body_hash = _body_hash(body)
        body_size = len(body)

        # ── 200 / 206 ─────────────────────────────────────────────────────────
        if code in (200, 206):
            # 1. Exact hash match against baseline random-404 responses
            if body_hash in baseline["hashes_200"]:
                return None
            full_hash = _body_hash_full(body)
            if full_hash in baseline["full_hashes_200"]:
                return None

            # 2. Homepage catch-all: same hash OR size within ±5% of homepage
            if baseline["homepage_full_hash"] and full_hash == baseline["homepage_full_hash"]:
                return None
            if baseline["homepage_size"] and _similar_size(body_size, baseline["homepage_size"]):
                return None

            # 3. Median-200 catch-all: if ALL random-404 probes returned 200,
            #    suppress responses that are within ±5% of that median size
            if baseline["returns_200"] and baseline["median_200"] and _similar_size(body_size, baseline["median_200"]):
                return None

            # 4. Too small to be a real file
            if body_size < 20 and severity not in ("info",):
                return None

            # 5. Generic "not found" text
            if body_size < 4000:
                lower = body_text.lower()
                if any(kw in lower for kw in [
                    "404", "not found", "page not found", "no encontrado",
                    "doesn't exist", "does not exist", "no existe", "error 404",
                    "could not be found", "nothing here", "no page",
                ]):
                    return None

            # 6. Magic bytes validation for binary formats
            if not _check_magic(path, body):
                return None

            # 7. HTML content-type for paths that must not be HTML
            if _should_reject_html(path) and _is_html_response(content_type):
                return None

            # 8. Content signature mismatch for known text formats
            if not _content_validates(path, body_text):
                return None

            return _make_result(path, url, code, body_size, content_type,
                                description, severity, body_text, confidence="high")

        # ── 403 ───────────────────────────────────────────────────────────────
        elif code == 403:
            # WAF block page (Cloudflare "you have been blocked", Sucuri, etc.)
            # — the scanner itself is blocked; nothing can be concluded.
            if _is_waf_block_page(body):
                return None

            # Only pursue high/critical paths for 403 — medium/low are too noisy
            if severity not in ("critical", "high"):
                return None

            # Body matches baseline 403 wall response → WAF block, not real file
            if body_hash in baseline["hashes_403"]:
                return None

            # Body size matches identified "wall size"
            if baseline["wall_size"] is not None and body_size == baseline["wall_size"]:
                return None

            # Server returns 403 for random paths → only trust TRUSTED_403_PATHS
            if baseline["returns_403"] and path not in TRUSTED_403_PATHS:
                return None

            # WAF present on baseline + WAF headers on this response + not trusted path
            if baseline["waf_on_baseline"] and _has_waf_header(resp.headers):
                if path not in TRUSTED_403_PATHS:
                    return None

            # ── Try bypass variants to confirm the resource ────────────────
            bypass_confirmed = False
            bypass_url = None
            bypass_snippet = None
            for variant in _bypass_variants(path):
                try:
                    vurl = base_url.rstrip("/") + variant
                    vr = await afetch(vurl, client=client, allow_redirects=False)
                    if vr.status_code == 200 and len(vr.content) > 50:
                        vtext = vr.content.decode("utf-8", errors="replace")
                        if _content_validates(path, vtext):
                            bypass_confirmed = True
                            bypass_url = vurl
                            bypass_snippet = vtext[:150].replace("\n", " ").strip()
                            break
                except Exception:
                    pass

            note = "confirmed via path bypass" if bypass_confirmed else "access forbidden — likely exists"
            final_severity = severity if bypass_confirmed else _downgrade(severity)
            confidence = "confirmed" if bypass_confirmed else "medium"

            result = _make_result(
                path, bypass_url or url,
                200 if bypass_confirmed else 403,
                body_size, None,
                f"{description} ({note})",
                final_severity, bypass_snippet,
                confidence=confidence,
            )
            # Internal only, stripped in _run_async: lets the orchestrator
            # cross-check this 403 body against every OTHER path's 403 body
            # from the same run (see WALL_MIN_HITS below) — a same-run wall
            # the 5-probe random baseline can't catch, since it only samples
            # random junk paths, never these deliberately sensitive-looking
            # ones a WAF is more likely to blanket-block by pattern.
            if not bypass_confirmed:
                result["_hash"] = body_hash
            return result

        # ── 401 ───────────────────────────────────────────────────────────────
        elif code == 401:
            # 401 = resource definitively exists (server challenges auth)
            if severity in ("critical", "high"):
                return _make_result(
                    path, url, code, body_size, content_type,
                    f"{description} (auth required — resource confirmed)",
                    severity, None, confidence="high",
                )

    return None


def _make_result(
    path: str, url: str, status: int, size: int,
    content_type: str | None, description: str, severity: str,
    body_text: str | None, confidence: str,
) -> dict:
    snippet = None
    if body_text and severity not in ("info",):
        snippet = body_text[:150].replace("\n", " ").strip() or None
    return {
        "path": path,
        "url": url,
        "status": status,
        "size": size,
        "content_type": (content_type or "").split(";")[0].strip() or None,
        "description": description,
        "severity": severity,
        "snippet": snippet,
        "confidence": confidence,
    }


# ─── Async orchestrator ───────────────────────────────────────────────────────

async def _run_async(domain: str) -> dict[str, Any]:
    base_url = f"https://{domain}"
    limits = httpx.Limits(max_connections=25, max_keepalive_connections=10)
    async with make_async_client(
        timeout=httpx.Timeout(8.0),
        headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
        limits=limits,
    ) as client:
        # Connectivity check – fall back to http
        try:
            r = await afetch(base_url, client=client)
            if r.status_code >= 500:
                raise ValueError("server error")
        except Exception:
            base_url = f"http://{domain}"

        # Step 1: baseline calibration
        baseline = await _get_baseline(client, base_url)
        logger.debug(
            f"[exposed] baseline: 403_random={baseline['returns_403']} "
            f"200_random={baseline['returns_200']} waf={baseline['waf_on_baseline']} "
            f"wall_size={baseline['wall_size']}"
        )

        # Step 2: probe all paths
        semaphore = asyncio.Semaphore(15)
        tasks = [
            _probe(client, base_url, path, desc, sev, semaphore, baseline)
            for path, desc, sev in SENSITIVE_PATHS
        ]
        results = await asyncio.gather(*tasks)

    found = [r for r in results if r is not None]

    # Same-run wall check: several sensitive-looking paths returning a
    # byte-identical 403 body is a WAF/catch-all blocking by pattern, not
    # confirmation that each one is a real file — the 5-probe random
    # baseline can't catch this because it only samples random junk, never
    # these deliberately sensitive-looking paths a WAF is more likely to
    # blanket-block. WALL_MIN_HITS=3 (not 2) so two genuinely related real
    # files sharing one legitimate "Forbidden" page aren't wrongly dropped.
    WALL_MIN_HITS = 3
    hash_counts: dict[str, int] = {}
    for f in found:
        h = f.get("_hash")
        if h:
            hash_counts[h] = hash_counts.get(h, 0) + 1
    wall_hashes = {h for h, c in hash_counts.items() if c >= WALL_MIN_HITS}
    suppressed_count = 0
    if wall_hashes:
        suppressed_count = sum(1 for f in found if f.get("_hash") in wall_hashes)
        logger.info(
            f"[exposed] {domain}: suppressing {suppressed_count} 403 hit(s) "
            f"sharing an identical body across {len(wall_hashes)} signature(s) "
            "— WAF/catch-all wall, not confirmed files"
        )
        found = [f for f in found if f.get("_hash") not in wall_hashes]
    for f in found:
        f.pop("_hash", None)

    # Sort: severity desc, then confidence (confirmed > high > medium)
    _conf_order = {"confirmed": 0, "high": 1, "medium": 2}
    found.sort(key=lambda x: (
        -SEVERITY_ORDER.get(x["severity"], 0),
        _conf_order.get(x.get("confidence", "medium"), 2),
    ))

    risk = "low"
    if any(f["severity"] == "critical" for f in found):
        risk = "critical"
    elif any(f["severity"] == "high" for f in found):
        risk = "high"
    elif any(f["severity"] == "medium" for f in found):
        risk = "medium"

    findings = []
    for f in found:
        if f["severity"] in ("critical", "high", "medium"):
            conf_tag = "" if f.get("confidence") == "high" else f" [{f.get('confidence','?')}]"
            findings.append(f"[{f['severity'].upper()}] {f['description']} → {f['path']}{conf_tag}")

    has_security_txt = any(f["path"] == "/.well-known/security.txt" for f in found)

    if baseline.get("waf_blocked"):
        findings.append(
            "[INFO] Scanner blocked by WAF (block page detected during baseline) — "
            "403-based exposures suppressed as unreliable this run"
        )
    if suppressed_count:
        findings.append(
            f"[INFO] Suppressed {suppressed_count} sensitive-path 403 hit(s) sharing an "
            "identical response body — WAF/catch-all wall, not confirmed as real files"
        )

    return {
        "status": "ok",
        "exposed": found,
        "total": len(found),
        "critical_count":  sum(1 for f in found if f["severity"] == "critical"),
        "high_count":      sum(1 for f in found if f["severity"] == "high"),
        "confirmed_count": sum(1 for f in found if f.get("confidence") in ("confirmed", "high")),
        "has_security_txt": has_security_txt,
        "baseline": {
            "returns_403_for_random": baseline["returns_403"],
            "returns_200_for_random": baseline["returns_200"],
            "waf_detected_baseline":  baseline["waf_on_baseline"],
            "wall_size":              baseline["wall_size"],
        },
        "risks_by_severity": {
            sev: [f for f in found if f["severity"] == sev]
            for sev in ["critical", "high", "medium", "low", "info"]
        },
        "risk": risk,
        "findings": findings,
    }


# ─── Entry point ──────────────────────────────────────────────────────────────

def run(domain: str) -> dict[str, Any]:
    import warnings
    warnings.filterwarnings("ignore")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_run_async(domain))
        loop.close()
        return result
    except Exception as e:
        logger.error(f"[exposed] {domain}: {e}")
        return {
            "status": "error", "error": str(e),
            "exposed": [], "total": 0,
            "critical_count": 0, "high_count": 0, "confirmed_count": 0,
            "has_security_txt": False,
            "baseline": {},
            "risks_by_severity": {},
            "risk": "low", "findings": [],
        }

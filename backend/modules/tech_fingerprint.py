"""
Technology Fingerprinting Module
Detects web technologies (and their versions when exposed) via HTTP headers,
HTML meta tags, asset URLs and cookies, then enriches the result with
ProjectDiscovery httpx's Wappalyzer-based detection when that tool is present.

Result keys consumed elsewhere:
  technologies  sorted list of names (asset inventory, smart_fuzz hints, nuclei tags)
  versions      {name: version} for the ones whose version could be read
"""
import copy
import httpx
import re
import logging
import threading
import time
from typing import Any

from modules import tools_runner
from modules.common import SSRFBlocked, fetch, user_agent

logger = logging.getLogger(__name__)

# Patterns: (technology_name, header_or_source, pattern)
# `source` is a lowercase response header name, "html", or "cookies" (the
# names of the cookies the server set).
TECH_PATTERNS = [
    # Servers
    ("Apache", "server", r"apache"),
    ("Nginx", "server", r"nginx"),
    ("IIS", "server", r"microsoft-iis"),
    ("LiteSpeed", "server", r"litespeed"),
    ("OpenResty", "server", r"openresty"),
    ("Tomcat", "server", r"apache-coyote|tomcat"),
    ("Kestrel", "server", r"kestrel"),
    ("Gunicorn", "server", r"gunicorn"),
    ("Caddy", "server", r"caddy"),
    ("Envoy", "server", r"envoy"),
    ("Amazon S3", "server", r"amazons3"),
    # Frameworks / Languages
    ("PHP", "x-powered-by", r"php"),
    ("PHP", "cookies", r"phpsessid"),
    ("ASP.NET", "x-powered-by", r"asp\.net"),
    ("ASP.NET", "x-aspnet-version", r".+"),
    ("ASP.NET", "cookies", r"asp\.net_sessionid"),
    ("Express.js", "x-powered-by", r"express"),
    ("Ruby on Rails", "x-powered-by", r"phusion passenger"),
    ("Laravel", "cookies", r"laravel_session"),
    ("Django", "cookies", r"csrftoken"),
    ("Java", "cookies", r"jsessionid"),
    # CDNs / Proxies
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("Fastly", "via", r"fastly"),
    ("Varnish", "via", r"varnish"),
    ("AWS CloudFront", "via", r"cloudfront"),
    ("AWS CloudFront", "x-amz-cf-id", r".+"),
    ("Azure Front Door", "x-azure-ref", r".+"),
    ("Akamai", "server", r"akamaighost"),
    ("Vercel", "x-vercel-id", r".+"),
    ("Netlify", "server", r"netlify"),
    # Security
    ("reCAPTCHA", "html", r"recaptcha"),
    ("hCaptcha", "html", r"hcaptcha"),
    # CMS
    ("WordPress", "html", r"wp-content|wp-includes"),
    ("WordPress", "link", r"wordpress|wp-json"),
    ("Drupal", "x-generator", r"drupal"),
    ("Drupal", "x-drupal-cache", r".+"),
    ("Drupal", "html", r"drupal-settings-json|/sites/default/files|drupal\.settings"),
    ("Joomla", "html", r"joomla|/media/system/js/|/components/com_"),
    ("Ghost", "html", r"ghost\.org"),
    ("Shopify", "html", r"cdn\.shopify\.com"),
    ("Magento", "html", r"magento|/static/frontend/"),
    ("Wix", "html", r"wix\.com"),
    ("Squarespace", "html", r"squarespace"),
    # JS Frameworks
    ("React", "html", r"react|__REACT|_reactRootContainer"),
    ("Vue.js", "html", r"vue\.js|__vue__"),
    ("Angular", "html", r"ng-version|angular"),
    ("Next.js", "x-powered-by", r"next\.js"),
    ("Next.js", "link", r"/_next/static"),
    ("Next.js", "html", r"/_next/static|__NEXT_DATA__"),
    ("Nuxt.js", "html", r"__NUXT__|/_nuxt/"),
    # Analytics
    ("Google Analytics", "html", r"google-analytics\.com|gtag\(|UA-\d+"),
    ("Google Tag Manager", "html", r"googletagmanager\.com"),
    ("Facebook Pixel", "html", r"connect\.facebook\.net"),
    # Misc
    ("jQuery", "html", r"jquery"),
    ("Bootstrap", "html", r"bootstrap"),
    ("Font Awesome", "html", r"font-awesome|fontawesome"),
]

# Version extraction: (technology_name, source, regex whose group 1 is the version)
VERSION_PATTERNS = [
    ("Nginx", "server", r"nginx/(\d[\w.\-]*)"),
    ("Apache", "server", r"apache/(\d[\d.]*)"),
    ("IIS", "server", r"microsoft-iis/(\d[\d.]*)"),
    ("OpenResty", "server", r"openresty/(\d[\d.]*)"),
    ("LiteSpeed", "server", r"litespeed/(\d[\d.]*)"),
    ("PHP", "x-powered-by", r"php/(\d[\d.]*)"),
    ("ASP.NET", "x-aspnet-version", r"(\d[\d.]*)"),
    ("Next.js", "x-powered-by", r"next\.js (\d[\d.]*)"),
    ("Drupal", "x-generator", r"drupal (\d[\d.]*)"),
]

# <meta name="generator" content="WordPress 6.4.2"> — canonical names for the
# generators worth reporting under their own name.
GENERATOR_NAMES = {
    "wordpress": "WordPress", "joomla": "Joomla", "drupal": "Drupal",
    "ghost": "Ghost", "typo3": "TYPO3", "hugo": "Hugo", "gatsby": "Gatsby",
    "magento": "Magento", "prestashop": "PrestaShop", "wix.com website builder": "Wix",
}
_GENERATOR_RE = re.compile(
    r"""<meta\s+[^>]*?(?:name=["']generator["'][^>]*?content=["']([^"']+)["']"""
    r"""|content=["']([^"']+)["'][^>]*?name=["']generator["'])""",
    re.IGNORECASE,
)
_GENERATOR_VERSION_RE = re.compile(r"^(.*?)[\s\-]*v?(\d+(?:\.\d+)+)")

# Only assets that ship with WordPress core carry the core version in ?ver=
# (jquery.min.js?ver= is jQuery's own version, not WordPress's).
_WP_CORE_VER_RE = re.compile(
    r"wp-includes/(?:js/wp-emoji-release\.min\.js|js/wp-embed\.min\.js|css/classic-themes\.min\.css"
    r"|css/dist/block-library/[\w.\-/]+\.css)\?ver=(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)
_WP_PLUGIN_RE = re.compile(r"wp-content/plugins/([\w\-]+)/[^\"'\s>]*?\?ver=(\d+(?:\.\d+)+)", re.IGNORECASE)
_WP_THEME_RE = re.compile(r"wp-content/themes/([\w\-]+)/[^\"'\s>]*?\?ver=(\d+(?:\.\d+)+)", re.IGNORECASE)
MAX_WP_EXTENSIONS = 15

# Wappalyzer (httpx -tech-detect) names → the names used above.
HTTPX_ALIASES = {
    "apache http server": "Apache", "microsoft asp.net": "ASP.NET", "microsoft iis": "IIS",
    "amazon cloudfront": "AWS CloudFront", "express": "Express.js", "nginx": "Nginx",
    "openresty": "OpenResty", "litespeed": "LiteSpeed", "apache tomcat": "Tomcat",
}
# Protocol/feature flags rather than technologies.
HTTPX_IGNORED = {"hsts", "http/3", "open graph", "rss", "priority hints", "http/2"}
HTTPX_TIMEOUT = 40

_CACHE_TTL = 90  # seconds — lets nuclei reuse the tech module's work in the same scan
_cache: dict[str, tuple[float, dict]] = {}
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _generators(html: str) -> list[tuple[str, str | None]]:
    """[(canonical name, version|None)] for the generators worth reporting."""
    out: list[tuple[str, str | None]] = []
    for m in _GENERATOR_RE.finditer(html):
        content = (m.group(1) or m.group(2) or "").strip()
        vm = _GENERATOR_VERSION_RE.match(content)
        name = (vm.group(1) if vm else content).strip(" !-").lower()
        canonical = GENERATOR_NAMES.get(name)
        if canonical is None:
            # "Joomla! - Open Source Content Management": the name is the lead word
            lead = re.split(r"[\s!\-]+", content.lower(), maxsplit=1)[0]
            canonical = GENERATOR_NAMES.get(lead)
        if canonical:
            out.append((canonical, vm.group(2) if vm else None))
    return out


def extract_versions(headers_lower: dict[str, str], html: str) -> dict[str, str]:
    """Versions readable from response headers, generator meta and asset URLs."""
    versions: dict[str, str] = {}
    for tech, source, pattern in VERSION_PATTERNS:
        text = headers_lower.get(source, "")
        m = re.search(pattern, text, re.IGNORECASE) if text else None
        if m and tech not in versions:
            versions[tech] = m.group(1)

    for name, version in _generators(html):
        if version and name not in versions:
            versions[name] = version

    core = _WP_CORE_VER_RE.search(html)
    if core and "WordPress" not in versions:
        versions["WordPress"] = core.group(1)
    return versions


def extract_wp_extensions(html: str) -> dict[str, str]:
    """{"<slug> (WP plugin)": version, "<slug> (WP theme)": version} from asset URLs."""
    found: dict[str, str] = {}
    for regex, label in ((_WP_PLUGIN_RE, "WP plugin"), (_WP_THEME_RE, "WP theme")):
        for slug, ver in regex.findall(html):
            name = f"{slug.lower()} ({label})"
            if name not in found and len(found) < MAX_WP_EXTENSIONS:
                found[name] = ver
    return found


def generator_technologies(html: str) -> set[str]:
    """Known generators named in <meta name="generator">, with or without version."""
    return {name for name, _ in _generators(html)}


def parse_httpx_tech(entries: list[str]) -> dict[str, str | None]:
    """httpx -tech-detect entries ("Nginx:1.18.0", "Ubuntu") → {name: version|None}."""
    out: dict[str, str | None] = {}
    for raw in entries or []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        name, _, version = raw.partition(":")
        name = name.strip()
        if name.lower() in HTTPX_IGNORED:
            continue
        name = HTTPX_ALIASES.get(name.lower(), name)
        out[name] = version.strip() or None
    return out


def _httpx_enrich(domain: str) -> tuple[dict[str, str | None], str]:
    """(technologies, status) from ProjectDiscovery httpx; never raises."""
    if not tools_runner.tool_enabled("httpx") or not tools_runner.which_tool("httpx"):
        return {}, "skipped"
    stdout, stderr, rc = tools_runner.run_tool(
        "httpx",
        ["-silent", "-json", "-tech-detect", "-follow-redirects", "-timeout", "10", "-no-color",
         "-H", f"User-Agent: {user_agent()}"],
        HTTPX_TIMEOUT, f"https://{domain}",
    )
    items = tools_runner._parse_jsonl(stdout)
    if not items:
        return {}, "error" if rc not in (0, 124) else "no_response"
    return parse_httpx_tech(items[0].get("tech") or []), "ok"


def _detect(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "ok",
        "technologies": [],
        "versions": {},
        "server": None,
        "powered_by": None,
        "cookies": [],
        "risk": "low",
        "findings": [],
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            resp = fetch(
                url,
                timeout=10,
                headers={"User-Agent": user_agent()},
            )
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            html = resp.text[:200000]  # WordPress asset URLs can sit well past the first 50KB

            result["server"] = resp.headers.get("Server") or resp.headers.get("server")
            result["powered_by"] = resp.headers.get("X-Powered-By") or resp.headers.get("x-powered-by")

            # Cookies analysis
            cookie_names = []
            for cookie in resp.cookies.jar:
                cookie_names.append(cookie.name.lower())
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite"),
                }
                result["cookies"].append(cookie_info)
                if not cookie.secure:
                    result["findings"].append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie_info["httponly"]:
                    result["findings"].append(f"Cookie '{cookie.name}' missing HttpOnly flag")

            # Technology detection
            detected = set()
            html_lower = html[:50000].lower()
            cookies_text = " ".join(cookie_names)
            for tech, source, pattern in TECH_PATTERNS:
                if source == "html":
                    text = html_lower
                elif source == "cookies":
                    text = cookies_text
                elif source in headers_lower:
                    text = headers_lower[source]
                else:
                    text = ""
                if text and re.search(pattern, text, re.IGNORECASE):
                    detected.add(tech)

            detected |= generator_technologies(html)
            versions = extract_versions(headers_lower, html)
            for name, ver in extract_wp_extensions(html).items():
                detected.add(name)
                versions[name] = ver
            detected |= set(versions)

            # Wappalyzer-based enrichment; header/HTML readings win on conflicts.
            enriched, httpx_status = _httpx_enrich(domain)
            result["httpx"] = httpx_status
            for name, ver in enriched.items():
                detected.add(name)
                if ver and name not in versions:
                    versions[name] = ver

            result["technologies"] = sorted(detected)
            result["versions"] = versions

            # Risk: exposing server version
            server = result["server"] or ""
            if re.search(r"\d+\.\d+", server):
                result["findings"].append(
                    f"Server header reveals version: '{server}' — could aid targeted attacks"
                )
                result["risk"] = "medium"

            if result["powered_by"]:
                result["findings"].append(
                    f"X-Powered-By header reveals: '{result['powered_by']}'"
                )
                if result["risk"] == "low":
                    result["risk"] = "low"  # informational

            break

        except (httpx.ConnectError, SSRFBlocked):
            continue
        except Exception as e:
            logger.error(f"[tech] {domain}: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            break

    return result


def run(domain: str) -> dict[str, Any]:
    """Detect once per domain per _CACHE_TTL: nuclei asks for the same
    technologies at the same moment as the tech module, and one probe (plus
    one httpx run) is enough for both."""
    with _locks_guard:
        lock = _locks.setdefault(domain, threading.Lock())
    with lock:
        hit = _cache.get(domain)
        if hit and time.time() - hit[0] < _CACHE_TTL:
            return copy.deepcopy(hit[1])
        result = _detect(domain)
        if result.get("status") == "ok":
            now = time.time()
            for stale in [k for k, (t, _) in _cache.items() if now - t > _CACHE_TTL]:
                _cache.pop(stale, None)
            _cache[domain] = (now, result)
        return copy.deepcopy(result)

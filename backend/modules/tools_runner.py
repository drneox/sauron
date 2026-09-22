"""
tools_runner.py — Shared runner for external security binaries
(ProjectDiscovery subfinder/httpx/katana/naabu + trufflesecurity/trufflehog).

Same philosophy as nuclei_integration: every tool is OPTIONAL. If the binary
is missing, or the tool is disabled via settings (tools_<name>), helpers
return {"status": "skipped", "reason": ...} instead of raising.

Execution rules:
  - subprocess with argv LIST, never shell=True
  - minimal PATH env for the child process
  - hard timeout per tool; on timeout the process is killed and partial
    stdout is still parsed (JSONL tools emit results incrementally)

Enable/disable flags are per-scan: main._run_scan calls set_tool_flags()
before running modules. Stored in a ContextVar so concurrent scan workers
(SCAN_WORKERS > 1) never see each other's flags. Default: all enabled.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
from contextvars import ContextVar
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TOOLS = ("subfinder", "httpx", "katana", "naabu", "trufflehog")

# Minimal PATH for child processes (covers Docker /usr/local/bin and macOS brew).
_CHILD_PATH = "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:" + str(Path.home() / ".local" / "bin")

# Fixed install locations checked BEFORE PATH: Docker installs to
# /usr/local/bin, brew to /opt/homebrew/bin. Fixed paths win so that e.g. a
# stray Python `httpx` console script on PATH can't shadow ProjectDiscovery's
# httpx. ~/.local/bin is the sudo-free fallback for host installs.
def _extra_dirs() -> tuple[str, ...]:
    return ("/usr/local/bin", str(Path.home() / ".local" / "bin"),
            "/opt/homebrew/bin", "/usr/bin")

_tool_flags: ContextVar[dict[str, bool]] = ContextVar("asm_tool_flags", default={})


def set_tool_flags(settings: dict[str, Any] | None) -> None:
    """Snapshot tools_* settings for the current scan (context-local)."""
    flags: dict[str, bool] = {}
    for name in TOOLS:
        value = (settings or {}).get(f"tools_{name}")
        flags[name] = value if isinstance(value, bool) else True
    _tool_flags.set(flags)


def tool_enabled(name: str) -> bool:
    return _tool_flags.get().get(name, True)


def which_tool(name: str) -> str | None:
    """Path to the binary, or None. Fixed install locations first, then PATH."""
    for directory in _extra_dirs():
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    home_go = Path.home() / "go" / "bin" / name
    if home_go.exists() and os.access(home_go, os.X_OK):
        return str(home_go)
    return shutil.which(name)


def run_tool(name: str, argv: list[str], timeout: int,
             input_text: str | None = None) -> tuple[str, str, int]:
    """Run `argv` (binary resolved via which_tool) without a shell.

    Returns (stdout, stderr, returncode). Never raises:
      - binary missing  → ("", "tool not installed", 127)
      - timeout         → (partial_stdout, "timeout after Ns", 124)
    """
    binary = which_tool(name)
    if not binary:
        return "", f"{name}: tool not installed", 127
    env = {"PATH": _CHILD_PATH, "HOME": os.environ.get("HOME", "/tmp")}
    cmd = [binary, *argv]
    logger.info(f"[tools] running: {' '.join(cmd)} (timeout={timeout}s)")
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout.decode("utf-8", errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        logger.warning(f"[tools] {name} timed out after {timeout}s — using partial output")
        return partial, f"timeout after {timeout}s", 124
    except Exception as exc:
        logger.error(f"[tools] {name} failed to start: {exc}")
        return "", str(exc), 1


def _skipped(name: str) -> dict[str, Any]:
    return {"status": "skipped", "reason": f"{name}: tool not installed or disabled in settings"}


def _parse_jsonl(stdout: str) -> list[dict]:
    items = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


# ── subfinder — passive subdomain enumeration ────────────────────────────────
SUBFINDER_TIMEOUT = 90


async def subfinder_subs(domain: str) -> dict[str, Any]:
    """subfinder -d <domain> -silent -json → list of subdomains.

    Uses passive sources only (no API keys configured → free sources, which
    may be rate-limited; partial results are still returned)."""
    if not tool_enabled("subfinder") or not which_tool("subfinder"):
        return _skipped("subfinder")
    stdout, stderr, rc = await asyncio.to_thread(
        run_tool, "subfinder", ["-d", domain, "-silent", "-json", "-timeout", "10"], SUBFINDER_TIMEOUT,
    )
    subs = sorted({
        str(item.get("host", "")).strip().lower()
        for item in _parse_jsonl(stdout)
        if item.get("host")
    })
    result: dict[str, Any] = {"status": "ok", "subdomains": subs, "count": len(subs)}
    if rc == 124:
        result["timed_out"] = True
    if rc not in (0, 124) and not subs:
        result["status"] = "error"
        result["error"] = stderr.strip()[:300]
    return result


# ── httpx (ProjectDiscovery) — HTTP probing / tech detection ────────────────
HTTPX_TIMEOUT = 60


async def httpx_probe(hosts: list[str]) -> dict[str, Any]:
    """httpx -silent -json -tech-detect -status-code -title over a host list.

    Hosts are piped via stdin. Returns one entry per alive host with its
    final URL, status code, page title and detected technologies."""
    if not tool_enabled("httpx") or not which_tool("httpx"):
        return _skipped("httpx")
    hosts = [h.strip() for h in hosts if h and h.strip()][:200]
    if not hosts:
        return {"status": "ok", "hosts": [], "alive_count": 0}
    stdout, stderr, rc = await asyncio.to_thread(
        run_tool, "httpx",
        ["-silent", "-json", "-tech-detect", "-status-code", "-title", "-timeout", "8", "-threads", "20"],
        HTTPX_TIMEOUT, "\n".join(hosts),
    )
    probed = []
    for item in _parse_jsonl(stdout):
        probed.append({
            "host":        item.get("host", ""),
            "url":         item.get("url", ""),
            "status_code": item.get("status_code"),
            "title":       item.get("title", ""),
            "tech":        item.get("tech", []) or [],
            "webserver":   item.get("webserver", ""),
        })
    result: dict[str, Any] = {"status": "ok", "hosts": probed, "alive_count": len(probed)}
    if rc == 124:
        result["timed_out"] = True
    if rc not in (0, 124) and not probed:
        result["status"] = "error"
        result["error"] = stderr.strip()[:300]
    return result


# ── katana — web crawler ──────────────────────────────────────────────────────
KATANA_TIMEOUT = 120


async def katana_crawl(domain: str, depth: int = 2, max_pages: int = 50) -> dict[str, Any]:
    """katana -u <domain> -silent -jsonl -d <depth> → discovered URLs.

    `urls` holds every endpoint seen; `js` is the subset ending in .js —
    useful to feed JS secret scanning beyond the homepage."""
    if not tool_enabled("katana") or not which_tool("katana"):
        return _skipped("katana")
    stdout, stderr, rc = await asyncio.to_thread(
        run_tool, "katana",
        ["-u", domain, "-silent", "-jsonl", "-d", str(depth),
         "-jc",                    # parse JS bundles for endpoints (SPAs!)
         "-kf", "robotstxt", "-kf", "sitemapxml",  # mine robots.txt + sitemap.xml
         "-c", "10", "-timeout", "10", "-max-response-size", "2097152"],
        KATANA_TIMEOUT,
    )
    urls: list[str] = []
    seen: set[str] = set()
    for item in _parse_jsonl(stdout):
        url = (item.get("request") or {}).get("endpoint") or item.get("url") or ""
        url = url.strip()
        if url and url not in seen and len(urls) < max_pages:
            seen.add(url)
            urls.append(url)
    js = [u for u in urls if u.split("?")[0].lower().endswith(".js")]
    result: dict[str, Any] = {
        "status": "ok", "urls": urls, "js": js,
        "count": len(urls), "js_count": len(js),
    }
    if rc == 124:
        result["timed_out"] = True
    if rc not in (0, 124) and not urls:
        result["status"] = "error"
        result["error"] = stderr.strip()[:300]
    return result


# ── naabu — fast port scanner ────────────────────────────────────────────────
NAABU_TIMEOUT = 120


async def naabu_scan(host: str, top_ports: int = 100) -> dict[str, Any]:
    """naabu -host <host> -top-ports <n> -silent -json → open ports.

    SYN-scan engine: much faster than connect() sockets for wide ranges.
    Without root/CAP_NET_RAW it falls back to connect scans internally
    (still parallel, usually faster than our ThreadPool over 38 ports).
    -stream disables naabu's verify/retries second pass (results arrive once).
    Returns only OPEN ports; banner/unauth enrichment stays in port_scan."""
    if not tool_enabled("naabu") or not which_tool("naabu"):
        return _skipped("naabu")
    stdout, stderr, rc = await asyncio.to_thread(
        run_tool, "naabu",
        ["-host", host, "-top-ports", str(top_ports), "-silent", "-json",
         "-stream", "-timeout", "1500", "-rate", "300"],
        NAABU_TIMEOUT,
    )
    ports = sorted({
        int(item["port"])
        for item in _parse_jsonl(stdout)
        if str(item.get("port", "")).isdigit()
    })
    result: dict[str, Any] = {"status": "ok", "host": host, "ports": ports, "count": len(ports)}
    if rc == 124:
        result["timed_out"] = True
    if rc not in (0, 124) and not ports:
        result["status"] = "error"
        result["error"] = stderr.strip()[:300]
    return result


# ── trufflehog — secret scanning over a LOCAL filesystem path ────────────────
TRUFFLEHOG_TIMEOUT = 120


async def trufflehog_fs(path: str | None) -> dict[str, Any]:
    """trufflehog filesystem <path> --json → verified/unverified secrets.

    LOCAL PATHS ONLY: this never clones repositories. The ASM scans remote
    attack surfaces and has no local checkout of the target's code, so this
    helper is a building block for a future "scan an uploaded repo" feature.
    Callers must pass an existing local directory; anything else is skipped."""
    if not tool_enabled("trufflehog") or not which_tool("trufflehog"):
        return _skipped("trufflehog")
    if not path or not Path(path).is_dir():
        return {
            "status": "skipped",
            "reason": "no local checkout path provided — trufflehog_fs never clones repos; "
                      "pass an existing local directory",
        }
    stdout, stderr, rc = await asyncio.to_thread(
        run_tool, "trufflehog",
        ["filesystem", path, "--json", "--no-update", "--fail"],
        TRUFFLEHOG_TIMEOUT,
    )
    secrets = []
    for item in _parse_jsonl(stdout):
        secrets.append({
            "detector":  item.get("DetectorName", ""),
            "verified":  bool(item.get("Verified")),
            "source":    ((item.get("SourceMetadata") or {}).get("Data") or {})
                         .get("Filesystem", {}).get("file", ""),
        })
    result: dict[str, Any] = {"status": "ok", "secrets": secrets, "count": len(secrets)}
    if rc == 124:
        result["timed_out"] = True
    # trufflehog exits 183 when it finds secrets with --fail; that's success for us
    if rc not in (0, 124, 183) and not secrets:
        result["status"] = "error"
        result["error"] = stderr.strip()[:300]
    return result

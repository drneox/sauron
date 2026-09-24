"""
Agent Scan — LLM-driven investigation phase.
Runs AFTER the deterministic pipeline and persistence, while the scan is still
"running" (current_module="agent"). The LLM investigates the compact scan
result through a strict allowlist of read-only tools, then closes the loop
with finish(summary). Never breaks the scan: every tool exception is returned
to the LLM as an error tool result.

Guardrails:
  - Scope: any tool target must be the scanned apex, a subdomain of it, or an
    explicitly allowed extra domain (company domains). Anything else is
    rejected and fed back to the LLM as a tool error.
  - max_steps: default 15, hard cap 30. Total timeout: 10 minutes.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable

import httpx
import tldextract

from modules import (
    admin_discovery,
    cookie_security,
    cors_check,
    dns_enum,
    dnssec_check,
    exposed_files,
    frontend_cve,
    headers_check,
    js_secrets,
    robots_sitemap,
    secret_verification,
    smart_fuzz,
    ssl_check,
    subdomain_enum,
    tech_fingerprint,
    tls_audit,
    waf_detect,
)
from modules.ai_summary import _build_compact_json, _chat_request

logger = logging.getLogger(__name__)

DEFAULT_MAX_STEPS = 15
RECON_MAX_STEPS = 25   # agent-only mode builds the whole picture itself
MAX_STEPS_CAP = 30
TOTAL_TIMEOUT_S = 600
LLM_TIMEOUT = 90
MAX_TOOL_RESULT_CHARS = 4_000
MAX_STEP_SUMMARY_CHARS = 500
MAX_NEW_FINDINGS_PER_STEP = 10

# Read-only modules the agent may re-run on in-scope targets.
SAFE_MODULES: dict[str, Callable[[str], dict]] = {
    "headers": headers_check.run,
    "tech": tech_fingerprint.run,
    "waf": waf_detect.run,
    "robots": robots_sitemap.run,
    "cors": cors_check.run,
    "cookies": cookie_security.run,
    "dnssec": dnssec_check.run,
    "ssl": ssl_check.run,
    "tls": tls_audit.run,
    "frontend_cve": frontend_cve.run,
    "dns": dns_enum.run,
}

_REASONING_PARAM = {"type": "string", "description": "Brief rationale for this action in Spanish (1-2 sentences, shown live to the user)"}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_module",
            "description": "Re-run a read-only deterministic scan module against an in-scope domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "module": {"type": "string", "enum": sorted(SAFE_MODULES)},
                    "domain": {"type": "string", "description": "In-scope target domain"},
                    "reasoning": _REASONING_PARAM,
                },
                "required": ["module", "domain", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_subdomains",
            "description": "Enumerate subdomains of an in-scope apex domain (passive sources + DNS brute-force).",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reasoning": _REASONING_PARAM},
                "required": ["domain", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mine_js",
            "description": "Crawl JS bundles of an in-scope domain and mine endpoints, hosts and candidate secrets.",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reasoning": _REASONING_PARAM},
                "required": ["domain", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_secrets",
            "description": "Actively verify the candidate secrets found by the last mine_js call (read-only GETs). Skipped if nothing was mined.",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reasoning": _REASONING_PARAM},
                "required": ["domain", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fuzz_paths",
            "description": "Wordlist-fuzz an in-scope domain for hidden paths (calibrated against false positives; capped at 500 requests).",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reasoning": _REASONING_PARAM},
                "required": ["domain", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_sensitive_files",
            "description": "Probe an in-scope domain for exposed sensitive files and admin panels (targeted list, fast).",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reasoning": _REASONING_PARAM},
                "required": ["domain", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Close the investigation with an executive summary in Spanish (markdown).",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    },
]

SYSTEM_PROMPT = (
    "Eres un agente de seguridad ofensiva defensiva (ASM). Acabas de recibir el resultado "
    "compacto de un escaneo determinista de superficie de ataque. Tu objetivo: investiga en "
    "profundidad los hallazgos más prometedores, verifica candidatos a secreto (mine_js → "
    "verify_secrets) y amplía la superficie si hay pistas (enumerate_subdomains, fuzz_paths). "
    "NO repitas run_module sobre el dominio apex para módulos que ya aparecen en el resultado "
    "determinista: ya tienes sus datos; úsalo sobre subdominios u otros dominios en scope. "
    "Solo puedes actuar sobre dominios dentro del scope indicado; cualquier otro target será "
    "rechazado. Cada vez que llames a una tool, rellena SIEMPRE su parámetro `reasoning` "
    "con 1-2 frases en español explicando por qué la ejecutas (se muestra en vivo al usuario). "
    "Cuando termines, llama a finish() con un resumen ejecutivo en español "
    "(markdown) orientado a un responsable de seguridad. No inventes hallazgos."
)


RECON_PROMPT = (
    " MODO RECONOCIMIENTO: no existe escaneo determinista previo; construye tú el panorama. "
    "Empieza con run_module sobre el dominio (dns, tech, headers, ssl, tls, waf, cors, cookies, robots), "
    "luego enumerate_subdomains, mine_js → verify_secrets y fuzz_paths según las pistas, y "
    "probe_sensitive_files si procede. Prioriza lo de mayor riesgo dentro del presupuesto. "
    "No puedes ejecutar whois, email, puertos, breach ni blacklist: no los menciones como "
    "hallazgos ni como cobertura, y aclara en el resumen que es un reconocimiento parcial."
)


def _registered(domain: str) -> str:
    ext = tldextract.extract(domain)
    return ext.registered_domain or domain


def _in_scope(target: str, apex: str, extra_allowed: set[str]) -> bool:
    target = (target or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not target:
        return False
    apex_reg = _registered(apex)
    allowed_regs = {_registered(d) for d in extra_allowed} | {apex_reg}
    if _registered(target) not in allowed_regs:
        return False
    # Within an allowed registered domain, only the apex itself or
    # subdomains of the scanned apex / allowed domains are in scope.
    bases = {apex} | {d.lower() for d in extra_allowed}
    return any(target == base or target.endswith("." + base) for base in bases)


def _summarize_tool_result(result: Any, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    try:
        text = json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        text = str(result)
    return text[:limit]


def _extract_tool_findings(tool: str, result: Any) -> list[str]:
    if not isinstance(result, dict):
        return []
    findings = result.get("findings") or []
    out = []
    for f in findings:
        if isinstance(f, str):
            out.append(f)
        elif isinstance(f, dict):
            out.append(f.get("finding") or json.dumps(f, ensure_ascii=False, default=str))
    return [f for f in out if f][:MAX_NEW_FINDINGS_PER_STEP]


def _novel_findings(findings: list[str], target: str, apex: str,
                    known: set[str], seen: set[tuple[str, str]]) -> list[str]:
    """Drop findings the deterministic scan already reported (only when the tool
    ran against the apex itself — the same text on a subdomain is a different
    finding) and repeats of the same finding on the same target across steps."""
    out = []
    for f in findings:
        if target == apex and f in known:
            continue
        if (target, f) in seen:
            continue
        seen.add((target, f))
        out.append(f)
    return out


class _AgentState:
    def __init__(self, apex: str, extra_allowed: set[str], ran_modules: set[str] | None = None) -> None:
        self.apex = apex
        self.extra_allowed = extra_allowed
        self.ran_modules = ran_modules or set()
        self.raw_secrets: dict | None = None
        self.finished = False
        self.summary: str = ""
        self.assets_discovered = 0

    def run_tool(self, name: str, args: dict) -> Any:
        target = str(args.get("domain") or args.get("target") or "").strip().lower()
        if name == "finish":
            self.finished = True
            self.summary = str(args.get("summary") or "")
            return {"status": "ok", "message": "Investigation closed"}
        if not _in_scope(target, self.apex, self.extra_allowed):
            return {"status": "error", "error": f"Out of scope: '{target}' is not the scanned apex or a subdomain/company domain of it"}
        if name == "run_module":
            module = str(args.get("module") or "")
            func = SAFE_MODULES.get(module)
            if func is None:
                return {"status": "error", "error": f"Module '{module}' is not allowed. Allowed: {sorted(SAFE_MODULES)}"}
            host = target.removeprefix("https://").removeprefix("http://").split("/")[0]
            if host == self.apex.strip().lower() and module in self.ran_modules:
                # Re-running it would return the same data the agent already has,
                # burning a step and extra requests against the target.
                return {"status": "skipped",
                        "reason": f"'{module}' already ran on {host} in the deterministic scan — "
                                  "its result is in your context. Investigate a subdomain or use another tool."}
            return func(target)
        if name == "enumerate_subdomains":
            result = subdomain_enum.run(target)
            self.assets_discovered += len(result.get("subdomains") or [])
            return result
        if name == "mine_js":
            result = js_secrets.run(target)
            self.raw_secrets = result.pop("_raw", None)
            self.assets_discovered += len(result.get("endpoints") or [])
            return result
        if name == "verify_secrets":
            if not self.raw_secrets:
                return {"status": "skipped", "reason": "no candidate secrets mined yet — call mine_js first"}
            return secret_verification.run(target, self.raw_secrets)
        if name == "fuzz_paths":
            result = smart_fuzz.run(target, wordlist="auto",
                                    max_requests=smart_fuzz.AGENT_MAX_REQUESTS)
            self.assets_discovered += len(result.get("paths_found") or [])
            return result
        if name == "probe_sensitive_files":
            result = exposed_files.run(target)
            try:
                admin = admin_discovery.run(target)
                result = dict(result)
                result["admin_panels"] = admin.get("found") or []
                for f in admin.get("findings") or []:
                    result.setdefault("findings", []).append(f)
            except Exception as e:
                result = dict(result)
                result["admin_error"] = str(e)
            return result
        return {"status": "error", "error": f"Unknown tool '{name}'"}


def run(
    domain: str,
    result: dict,
    max_steps: int = DEFAULT_MAX_STEPS,
    extra_allowed: set[str] | None = None,
    on_step: Callable[[dict], None] | None = None,
    recon: bool = False,
) -> dict[str, Any]:
    """Run the agent loop against a completed deterministic scan result
    (or, with recon=True, from scratch with no prior scan).

    Returns {"status": "ok"|"error"|"skipped", "steps": [...], "summary": str,
    "findings": [{"module": "agent", "finding", "risk"}], "assets_discovered": int,
    "error": str|None}.
    """
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        return {"status": "skipped", "steps": [], "summary": "", "findings": [],
                "assets_discovered": 0, "error": "AI not configured"}

    max_steps = max(1, min(int(max_steps or DEFAULT_MAX_STEPS), MAX_STEPS_CAP))
    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")

    ran_modules = {
        name for name, m in (result.get("modules") or {}).items()
        if isinstance(m, dict) and m.get("status") not in ("error", "skipped")
    }
    state = _AgentState(domain, {d.lower() for d in (extra_allowed or set())}, ran_modules)
    scope_desc = ", ".join(sorted({domain} | state.extra_allowed))

    if recon:
        user_msg = (
            f"Dominio a investigar (apex): {domain}\n"
            f"Dominios adicionales en scope: {scope_desc}\n"
            f"Presupuesto: {max_steps} pasos como máximo. Termina con finish().\n"
            "MODO RECONOCIMIENTO: no hay escaneo determinista previo, parte de cero."
        )
        system_msg = SYSTEM_PROMPT + RECON_PROMPT
    else:
        user_msg = (
            f"Dominio escaneado (apex): {domain}\n"
            f"Dominios adicionales en scope: {scope_desc}\n"
            f"Presupuesto: {max_steps} pasos como máximo. Termina con finish().\n"
            f"Resultado del escaneo determinista:\n{_build_compact_json(result)}"
        )
        system_msg = SYSTEM_PROMPT
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]

    steps: list[dict] = []
    agent_findings: list[dict] = []
    started = time.time()
    known_findings = {
        f if isinstance(f, str) else str(f.get("finding") or "")
        for f in (result.get("findings") or [])
    }
    seen_findings: set[tuple[str, str]] = set()

    def _record_step(tool: str, target: str, reasoning: str, tool_result: Any, duration: float) -> None:
        new_findings = _novel_findings(
            _extract_tool_findings(tool, tool_result),
            (target or "").strip().lower(), domain.strip().lower(),
            known_findings, seen_findings,
        )
        step = {
            "n": len(steps) + 1,
            "tool": tool,
            "target": target,
            "reasoning": (reasoning or "")[:1000],
            "result_summary": _summarize_tool_result(tool_result, MAX_STEP_SUMMARY_CHARS),
            "new_findings": new_findings,
            "duration_s": round(duration, 2),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        steps.append(step)
        risk = tool_result.get("risk", "low") if isinstance(tool_result, dict) else "low"
        for f in new_findings:
            agent_findings.append({"module": "agent", "finding": f"[{tool}] {f}", "risk": risk})
        if on_step:
            try:
                on_step(step)
            except Exception:
                pass

    try:
        with httpx.Client(timeout=LLM_TIMEOUT) as client:
            while len(steps) < max_steps and not state.finished:
                if time.time() - started > TOTAL_TIMEOUT_S:
                    logger.warning("Agent scan for %s hit total timeout", domain)
                    break
                payload = {
                    "model": model,
                    "messages": messages,
                    "tools": TOOLS,
                    "tool_choice": "auto",
                    "temperature": 0.3,
                }
                data = _chat_request(client, base_url, api_key, payload)
                msg = data["choices"][0]["message"]
                tool_calls = msg.get("tool_calls") or []
                reasoning = msg.get("content") or ""

                if not tool_calls:
                    # Model answered in plain text: accept it as the final summary.
                    if reasoning.strip():
                        state.summary = reasoning.strip()
                        state.finished = True
                    break

                messages.append({
                    "role": "assistant",
                    "content": msg.get("content"),
                    "tool_calls": tool_calls,
                })
                for call in tool_calls:
                    if len(steps) >= max_steps or time.time() - started > TOTAL_TIMEOUT_S:
                        break
                    func = call.get("function") or {}
                    tool_name = func.get("name") or ""
                    try:
                        tool_args = json.loads(func.get("arguments") or "{}")
                    except json.JSONDecodeError:
                        tool_args = {}
                    step_reasoning = str(tool_args.pop("reasoning", "") or "") or (msg.get("content") or "")
                    t0 = time.time()
                    try:
                        tool_result = state.run_tool(tool_name, tool_args)
                    except Exception as e:
                        logger.exception("Agent tool %s crashed", tool_name)
                        tool_result = {"status": "error", "error": str(e)}
                    duration = time.time() - t0
                    target = str(tool_args.get("domain") or tool_args.get("target") or tool_args.get("module") or "")
                    _record_step(tool_name, target, step_reasoning, tool_result, duration)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.get("id"),
                        "content": _summarize_tool_result(tool_result),
                    })
                    if state.finished:
                        break

        if not state.summary:
            state.summary = "El agente agotó su presupuesto de pasos sin cerrar con finish()."
        status = "ok" if state.finished else "incomplete"
        return {
            "status": status,
            "steps": steps,
            "summary": state.summary,
            "findings": agent_findings,
            "assets_discovered": state.assets_discovered,
            "error": None,
        }
    except Exception as e:
        logger.exception("Agent scan failed for %s", domain)
        return {
            "status": "error",
            "steps": steps,
            "summary": state.summary,
            "findings": agent_findings,
            "assets_discovered": state.assets_discovered,
            "error": str(e),
        }

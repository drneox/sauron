"""
AI Chat Assistant — read-only copilot over the Sauron ASM database.
Answers questions about companies, domains, scans, assets, findings and dates
via OpenAI-compatible function calling. Every tool is a READ-ONLY async query
against Tortoise; the assistant never writes to the DB. LLM config comes from
AI_API_KEY / AI_BASE_URL / AI_MODEL (same env as ai_summary / agent_scan); the
endpoint reports "not configured" when AI_API_KEY is missing.
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

import httpx

from db import Asset, Company, Domain, Scan
from modules.ai_summary import _endpoint_and_headers

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 6
TOTAL_TIMEOUT_S = 90
LLM_TIMEOUT = 60
MAX_TOOL_RESULT_CHARS = 8_000
ASSETS_CAP = 50
SCANS_CAP = 20
FINDINGS_CAP = 50
NEW_ASSET_DAYS = 7
ASSET_TYPES = ("subdomain", "ip", "endpoint", "technology", "app",
               "admin_panel", "exposed_file", "neighbor", "port")

SYSTEM_PROMPT = (
    "Eres SauronBot, el asistente de IA de Sauron ASM (Attack Surface Management). "
    "Tu personalidad: alegre, cercana y entusiasta — te encanta hablar de activos, "
    "scans y hallazgos. Usas un tono positivo y humano (sin exagerar), y de vez en "
    "cuando un emoji con moderación (✨🔍🎯🛡️). Si no sabes algo, lo dices con "
    "honestidad y buen humor.\n"
    "La base de datos contiene: empresas (companies), cada una con dominios; TAMBIÉN "
    "hay dominios sueltos sin empresa (scans rápidos independientes); scans "
    "de seguridad por dominio (status queued/running/completed/failed/interrupted, "
    "con grade A-F y score en el scorecard); un inventario de activos por dominio "
    "(tipos: subdomain, ip, endpoint, technology, app, admin_panel, exposed_file, "
    "neighbor, port) con first_seen/last_seen; y findings (hallazgos con riesgo "
    "low/medium/high/critical) del último scan completado de cada dominio.\n"
    "La fecha y hora actual es {now} (UTC). Para preguntas relativas como 'esta "
    "semana' u 'ayer', calcula las fechas a partir de hoy.\n"
    "Reglas estrictas:\n"
    "- Responde SIEMPRE en español, de forma concisa y con números exactos.\n"
    "- Usa SOLO datos devueltos por los tools; nunca inventes empresas, dominios, "
    "conteos ni hallazgos. Si un tool no devuelve datos, dilo claramente.\n"
    "- Los nombres de empresa y dominio admiten coincidencia parcial (p. ej. "
    "'pacifico' encuentra 'pacifico seguros'). Si el usuario pregunta por algo que "
    "no está en ninguna empresa, busca también en los dominios sin empresa.\n"
    "- NUNCA muestres claves, tokens ni contraseñas completas: si un dato parece "
    "un secreto, muéstralo redactado (primeros 4 + *** + últimos 3).\n"
    "- Cita fechas en formato corto (YYYY-MM-DD).\n"
    "- Formato: markdown simple (negritas y bullets con '- '); NUNCA uses tablas."
)


class AINotConfigured(Exception):
    pass


class AIBackendError(Exception):
    pass


# ── Tool implementations (READ-ONLY) ──────────────────────────────────────────

def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


async def _domain_ids_for(company_name: str | None, domain: str | None) -> tuple[list[int], list[str]]:
    qs = Domain.all()
    if company_name:
        comp = await Company.get_or_none(name__icontains=company_name)
        if comp is None:
            return [], []
        qs = qs.filter(company_id=comp.id)
    if domain:
        qs = qs.filter(domain__icontains=domain)
    rows = await qs.order_by("domain")
    return [d.id for d in rows], [d.domain for d in rows]


async def _tool_list_companies() -> dict:
    out = []
    for c in await Company.all().order_by("name"):
        domains = await Domain.filter(company_id=c.id).order_by("domain")
        dom_list = []
        latest_grade, latest_scan_at = None, None
        for d in domains:
            latest = await Scan.filter(domain_id=d.id, status="completed") \
                .order_by("-completed_at", "-started_at").first()
            grade = (latest.scorecard or {}).get("grade") if latest else None
            scan_at = latest.completed_at if latest else None
            if scan_at and (latest_scan_at is None or scan_at > latest_scan_at):
                latest_scan_at = scan_at
                latest_grade = grade
            dom_list.append({
                "domain": d.domain,
                "last_grade": grade,
                "last_scan_at": _iso(scan_at),
            })
        out.append({
            "name": c.name,
            "domain_count": len(domains),
            "last_grade": latest_grade,
            "last_scan_at": _iso(latest_scan_at),
            "domains": dom_list,
        })

    # Standalone domains (quick scans not linked to any company)
    orphans = await Domain.filter(company_id__isnull=True).order_by("domain")
    if orphans:
        dom_list = []
        for d in orphans:
            latest = await Scan.filter(domain_id=d.id, status="completed") \
                .order_by("-completed_at", "-started_at").first()
            dom_list.append({
                "domain": d.domain,
                "last_grade": (latest.scorecard or {}).get("grade") if latest else None,
                "last_scan_at": _iso(latest.completed_at if latest else None),
            })
        out.append({
            "name": "(standalone domains — no company)",
            "domain_count": len(orphans),
            "last_grade": None,
            "last_scan_at": None,
            "domains": dom_list,
        })
    return {"companies": out, "count": len(out)}


async def _tool_company_assets(company_name: str, asset_type: str | None = None,
                               search: str | None = None, only_new: bool = False) -> dict:
    domain_ids, domain_names = await _domain_ids_for(company_name, None)
    if not domain_ids:
        return {"error": f"No company/domain found matching '{company_name}'", "assets": [], "total_matching": 0}
    qs = Asset.filter(domain_id__in=domain_ids)
    if asset_type:
        qs = qs.filter(type=asset_type)
    if search:
        qs = qs.filter(value__icontains=search)
    if only_new:
        cutoff = datetime.now(timezone.utc) - timedelta(days=NEW_ASSET_DAYS)
        qs = qs.filter(first_seen_at__gte=cutoff)
    total = await qs.count()
    rows = await qs.order_by("-first_seen_at").limit(ASSETS_CAP).prefetch_related("domain")
    return {
        "company_scope": domain_names,
        "only_new_window_days": NEW_ASSET_DAYS if only_new else None,
        "total_matching": total,
        "returned": len(rows),
        "assets": [{
            "domain": a.domain.domain,
            "type": a.type,
            "value": a.value,
            "first_seen_at": _iso(a.first_seen_at),
            "last_seen_at": _iso(a.last_seen_at),
        } for a in rows],
    }


async def _tool_count_assets(company_name: str | None = None, asset_type: str | None = None) -> dict:
    qs = Asset.all()
    scope: list[str] = []
    if company_name:
        domain_ids, scope = await _domain_ids_for(company_name, None)
        if not domain_ids:
            return {"error": f"No company/domain found matching '{company_name}'", "by_type": {}, "total": 0}
        qs = qs.filter(domain_id__in=domain_ids)
    if asset_type:
        qs = qs.filter(type=asset_type)
    by_type = {t: await qs.filter(type=t).count() for t in ASSET_TYPES}
    by_type = {t: n for t, n in by_type.items() if n > 0}
    return {"scope": scope or "all companies", "by_type": by_type, "total": sum(by_type.values())}


async def _tool_list_scans(domain: str | None = None, company_name: str | None = None,
                           status: str | None = None, days_back: int | None = None) -> dict:
    qs = Scan.all()
    scope: list[str] = []
    if domain or company_name:
        domain_ids, scope = await _domain_ids_for(company_name, domain)
        if not domain_ids:
            return {"error": "No domain in scope matched the filters", "scans": [], "total_matching": 0}
        qs = qs.filter(domain_id__in=domain_ids)
    if status:
        qs = qs.filter(status=status)
    if days_back:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(days_back))
        qs = qs.filter(started_at__gte=cutoff)
    total = await qs.count()
    rows = await qs.order_by("-started_at").limit(SCANS_CAP).prefetch_related("domain")
    return {
        "scope": scope or "all domains",
        "total_matching": total,
        "returned": len(rows),
        "scans": [{
            "scan_id": s.id,
            "domain": s.domain.domain,
            "status": s.status,
            "grade": (s.scorecard or {}).get("grade"),
            "score": (s.scorecard or {}).get("score"),
            "started_at": _iso(s.started_at),
            "completed_at": _iso(s.completed_at),
        } for s in rows],
    }


async def _tool_findings(domain: str | None = None, company_name: str | None = None,
                         risk: str | None = None, days_back: int | None = None) -> dict:
    domain_ids, scope = await _domain_ids_for(company_name, domain)
    if not domain_ids:
        return {"error": "No domain in scope matched the filters", "findings": [], "total_matching": 0}
    cutoff = None
    if days_back:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(days_back))
    out: list[dict] = []
    for dom_id, dom_name in zip(domain_ids, scope):
        qs = Scan.filter(domain_id=dom_id, status="completed")
        if cutoff:
            qs = qs.filter(completed_at__gte=cutoff)
        latest = await qs.order_by("-completed_at", "-started_at").first()
        if latest is None or not latest.result:
            continue
        for f in (latest.result.get("findings") or []):
            if not isinstance(f, dict):
                continue
            if risk and f.get("risk") != risk:
                continue
            out.append({
                "domain": dom_name,
                "scan_id": latest.id,
                "scan_completed_at": _iso(latest.completed_at),
                "module": f.get("module"),
                "risk": f.get("risk"),
                "finding": f.get("finding"),
            })
    out.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.get("risk") or "", 4))
    return {
        "scope": scope,
        "source": "latest completed scan per domain",
        "total_matching": len(out),
        "returned": min(len(out), FINDINGS_CAP),
        "findings": out[:FINDINGS_CAP],
    }


async def _tool_emails_exposed(domain: str) -> dict:
    dom = await Domain.get_or_none(domain__icontains=domain)
    if dom is None:
        return {"error": f"No domain found matching '{domain}'", "emails": []}
    latest = await Scan.filter(domain_id=dom.id, status="completed") \
        .order_by("-completed_at", "-started_at").first()
    if latest is None or not latest.result:
        return {"domain": dom.domain, "error": "No completed scan for this domain", "emails": []}
    breach = (latest.result.get("modules") or {}).get("breach") or {}
    hunter = breach.get("hunter") or {}
    return {
        "domain": dom.domain,
        "scan_id": latest.id,
        "scan_completed_at": _iso(latest.completed_at),
        "combo_count": breach.get("combo_count", 0),
        "all_emails": breach.get("all_emails") or [],
        "hunter_emails": [e.get("email") for e in (hunter.get("emails") or []) if isinstance(e, dict)],
        "combo_samples": breach.get("combo_samples") or [],
    }


TOOL_FUNCS: dict[str, Callable[..., Awaitable[dict]]] = {
    "list_companies": _tool_list_companies,
    "company_assets": _tool_company_assets,
    "count_assets": _tool_count_assets,
    "list_scans": _tool_list_scans,
    "findings": _tool_findings,
    "emails_exposed": _tool_emails_exposed,
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_companies",
            "description": "List all companies with their domain count, last scan grade and last scan date.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "company_assets",
            "description": "List assets (subdomains, IPs, endpoints, technologies, apps, admin panels, exposed files, neighbors, ports) of a company, with first_seen/last_seen. Max 50.",
            "parameters": {
                "type": "object",
                "properties": {
                    "company_name": {"type": "string", "description": "Company name (partial match ok)"},
                    "asset_type": {"type": "string", "enum": list(ASSET_TYPES)},
                    "search": {"type": "string", "description": "Substring filter on the asset value"},
                    "only_new": {"type": "boolean", "description": "Only assets first seen in the last 7 days"},
                },
                "required": ["company_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "count_assets",
            "description": "Count assets grouped by type, optionally for one company and/or one asset type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "company_name": {"type": "string", "description": "Company name (partial match ok); omit for all companies"},
                    "asset_type": {"type": "string", "enum": list(ASSET_TYPES)},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_scans",
            "description": "List scans with status, grade and dates. Filters by domain, company, status and recency. Max 20.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "company_name": {"type": "string"},
                    "status": {"type": "string", "enum": ["queued", "running", "completed", "failed", "interrupted"]},
                    "days_back": {"type": "integer", "description": "Only scans started in the last N days"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "findings",
            "description": "Findings from the latest completed scan of each domain in scope, filterable by risk and recency. Max 50.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "company_name": {"type": "string"},
                    "risk": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "days_back": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "emails_exposed",
            "description": "Exposed/leaked emails of a domain from its latest completed scan (breach module: merged emails, hunter.io hits, combo-list samples).",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
            },
        },
    },
]


def _tool_arg_names(name: str) -> set[str]:
    for t in TOOLS:
        if t["function"]["name"] == name:
            return set(t["function"]["parameters"].get("properties") or {})
    return set()


def _result_count(result: Any) -> int:
    if not isinstance(result, dict):
        return 0
    for key in ("companies", "assets", "scans", "findings", "all_emails"):
        value = result.get(key)
        if isinstance(value, list):
            return len(value)
    if "total" in result and isinstance(result["total"], int):
        return result["total"]
    return 0


async def _async_chat_request(client: httpx.AsyncClient, base_url: str, api_key: str, payload: dict) -> dict:
    url, headers = _endpoint_and_headers(base_url, api_key)
    resp = await client.post(url, json=payload, headers=headers)
    resp.raise_for_status()
    return resp.json()


async def answer(message: str, history: list[dict] | None = None) -> dict[str, Any]:
    """Run the function-calling loop. Returns {"reply": str, "tools_used": [...]}.
    Raises AINotConfigured without AI_API_KEY, AIBackendError on LLM failures."""
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        raise AINotConfigured()

    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT.format(now=now)}]
    for h in (history or [])[-10:]:
        role, content = h.get("role"), str(h.get("content") or "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content[:2000]})
    messages.append({"role": "user", "content": message})

    tools_used: list[dict] = []
    started = time.time()

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            for _ in range(MAX_ITERATIONS):
                if time.time() - started > TOTAL_TIMEOUT_S:
                    break
                payload = {
                    "model": model,
                    "messages": messages,
                    "tools": TOOLS,
                    "tool_choice": "auto",
                    "temperature": 0.2,
                }
                data = await _async_chat_request(client, base_url, api_key, payload)
                msg = data["choices"][0]["message"]
                tool_calls = msg.get("tool_calls") or []

                if not tool_calls:
                    reply = (msg.get("content") or "").strip()
                    if reply:
                        return {"reply": reply, "tools_used": tools_used}
                    break

                messages.append({
                    "role": "assistant",
                    "content": msg.get("content"),
                    "tool_calls": tool_calls,
                })
                for call in tool_calls:
                    func = call.get("function") or {}
                    name = func.get("name") or ""
                    try:
                        args = json.loads(func.get("arguments") or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    func_impl = TOOL_FUNCS.get(name)
                    if func_impl is None:
                        result: Any = {"error": f"Unknown tool '{name}'"}
                    else:
                        args = {k: v for k, v in args.items() if k in _tool_arg_names(name)}
                        try:
                            result = await func_impl(**args)
                        except Exception as e:
                            logger.exception("Chat tool %s failed", name)
                            result = {"error": str(e)}
                    tools_used.append({"tool": name, "args": args, "result_count": _result_count(result)})
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.get("id"),
                        "content": json.dumps(result, ensure_ascii=False, default=str)[:MAX_TOOL_RESULT_CHARS],
                    })
    except AINotConfigured:
        raise
    except Exception as e:
        logger.exception("Chat assistant LLM call failed")
        raise AIBackendError(str(e)) from e

    raise AIBackendError("El asistente agotó sus iteraciones sin producir respuesta")

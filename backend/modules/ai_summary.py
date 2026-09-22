"""
AI Executive Summary (optional layer, not a scan module).
Runs AFTER the scorecard inside _run_scan; its output is stored in
result["ai_summary"] and never affects scoring. Without AI_API_KEY it
returns {"status": "skipped"}. It must NEVER break a scan.
"""
import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

MAX_PAYLOAD_CHARS = 30_000
TIMEOUT = 60

SYSTEM_PROMPT = (
    "Eres un analista ASM (Attack Surface Management) senior. Recibes el resultado "
    "compacto en JSON de un escaneo de superficie de ataque (scorecard, findings y "
    "riesgo por módulo). Redacta un análisis ejecutivo en español, claro y accionable, "
    "orientado a responsables de seguridad sin tiempo que perder. "
    "Responde ÚNICAMENTE con un objeto JSON válido con estas claves exactas:\n"
    '- "executive_summary": string en markdown (3-6 párrafos cortos o bullets) con el estado '
    "general del perímetro, lo más crítico y la prioridad de actuación.\n"
    '- "attack_scenarios": lista de strings; escenarios de ataque realistas derivados de los '
    "hallazgos (cadenas concretas, no genéricos).\n"
    '- "remediation_plan": lista ordenada de objetos {"action": string, "effort": "low"|"medium"|"high", '
    '"impact": "low"|"medium"|"high"}, de mayor impacto/esfuerzo favorable a menor.\n'
    "No inventes hallazgos que no estén en la entrada. No incluyas texto fuera del JSON."
)


def _build_compact_json(result: dict) -> str:
    compact: dict[str, Any] = {
        "domain": result.get("domain"),
        "scorecard": result.get("scorecard"),
        "findings": result.get("findings", [])[:100],
        "modules": {
            name: {
                "risk": mod.get("risk"),
                "findings": (mod.get("findings") or [])[:20],
            }
            for name, mod in (result.get("modules") or {}).items()
            if isinstance(mod, dict)
        },
    }
    return json.dumps(compact, ensure_ascii=False)[:MAX_PAYLOAD_CHARS]


def _endpoint_and_headers(base_url: str, api_key: str) -> tuple[str, dict]:
    """Resolve the final URL and auth header. Azure endpoints (AI Foundry /
    Azure OpenAI) carry the deployment and api-version in the URL and use the
    `api-key` header; OpenAI-compatible providers use Bearer + /chat/completions."""
    url = base_url if "/chat/completions" in base_url else f"{base_url}/chat/completions"
    if "azure" in base_url.lower():
        return url, {"api-key": api_key}
    return url, {"Authorization": f"Bearer {api_key}"}


def _chat_request(client: httpx.Client, base_url: str, api_key: str, payload: dict) -> dict:
    url, headers = _endpoint_and_headers(base_url, api_key)
    resp = client.post(url, json=payload, headers=headers)
    if resp.status_code == 400 and "response_format" in payload:
        # Provider does not support JSON mode — retry without it
        payload = {k: v for k, v in payload.items() if k != "response_format"}
        resp = client.post(url, json=payload, headers=headers)
    resp.raise_for_status()
    return resp.json()


def run(result: dict) -> dict[str, Any]:
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        return {"status": "skipped"}

    base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")

    try:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_compact_json(result)},
            ],
            "temperature": 0.3,
            "response_format": {"type": "json_object"},
        }
        with httpx.Client(timeout=TIMEOUT) as client:
            data = _chat_request(client, base_url, api_key, payload)

        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return {
            "status": "ok",
            "executive_summary": parsed.get("executive_summary", ""),
            "attack_scenarios": parsed.get("attack_scenarios") or [],
            "remediation_plan": parsed.get("remediation_plan") or [],
        }
    except Exception as e:
        logger.error(f"AI summary generation failed: {e}")
        return {"status": "error", "error": str(e)}

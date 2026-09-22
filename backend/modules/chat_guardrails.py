"""
Chat guardrails — input prompt-injection screening and output secret redaction
for the AI chat assistant (POST /api/chat).

- Input rail: regexes over the user message detect prompt-injection attempts;
  a match short-circuits the endpoint with a friendly SauronBot rejection (in
  Spanish, matching the assistant's persona) WITHOUT calling the LLM.
- Output rail: the LLM reply is scanned with the same secret patterns used by
  the js_secrets scanner; every match is replaced by <first 4>***<last 3> and
  the number of redactions is reported back.
"""
import logging
import re

from modules.js_secrets import SECRET_PATTERNS

logger = logging.getLogger(__name__)

# Case-insensitive prompt-injection heuristics over the raw user message.
INJECTION_PATTERNS = (
    r"ignore (all )?instructions",
    r"act as",
    r"you are now",
    r"reveal (your|the) (system )?prompt",
    r"system prompt",
    r"jailbreak",
    r"dan mode",
    r"override",
)
_COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

# Friendly refusal, in Spanish with the SauronBot persona. Kept generic on
# purpose: it never acknowledges which pattern fired.
BLOCKED_REPLY = (
    "Esa no me la esperaba 😄, pero mi misión es hablar de tu superficie de "
    "ataque: activos, scans y hallazgos. ¿Me preguntas mejor cuántos activos "
    "nuevos aparecieron esta semana? 🔍"
)

_COMPILED_SECRETS = [(label, re.compile(pattern)) for label, pattern, _sev in SECRET_PATTERNS]


def check_input(message: str) -> str | None:
    """Input rail. Returns the rejection reply when the message looks like a
    prompt-injection attempt, or None when it is safe to forward to the LLM."""
    for pattern in _COMPILED_INJECTION:
        if pattern.search(message):
            logger.warning(
                "Chat input rail blocked message (pattern=%r): %.120s",
                pattern.pattern, message,
            )
            return BLOCKED_REPLY
    return None


def _redact_value(value: str) -> str:
    if len(value) > 7:
        return f"{value[:4]}***{value[-3:]}"
    return "***"


def redact_secrets(text: str) -> tuple[str, int]:
    """Output rail. Replaces every secret-looking match in the LLM reply with
    '<first 4>***<last 3>'. Returns (sanitized_text, redacted_count)."""
    count = 0

    def _repl(match: re.Match) -> str:
        nonlocal count
        count += 1
        return _redact_value(match.group(0))

    sanitized = text
    for label, pattern in _COMPILED_SECRETS:
        sanitized = pattern.sub(_repl, sanitized)
    if count:
        logger.info("Chat output rail redacted %d secret(s) from the assistant reply", count)
    return sanitized, count

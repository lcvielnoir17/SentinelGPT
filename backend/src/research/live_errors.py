"""Safe provider-error diagnostics (M19 debugging only, offline).

``collect_transcripts()`` historically recorded only the exception class
name for ``provider_failed`` attempts, so a 12/12 failure run leaves no
actionable signal in the persisted artifacts (the per-attempt summary is
in-memory only; ``live-evaluation.json`` keeps aggregates). This helper
builds a redacted one-line diagnostic instead:

* exception class
* numeric provider/HTTP status when present
* retryability classification
* sanitized message fragment

It never includes request bodies, evidence, prompts, keys, tokens,
cookies, credential values, or URLs carrying credentials. Only the
exception's own class/message (plus numeric ``code``/``status_code``
attributes when the SDK sets them) are read.
"""

from __future__ import annotations

import re

MAX_DIAGNOSTIC_CHARS = 500

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(https?://)[^/\s:@]+:[^@\s]+@"), r"\1[redacted]@"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{4,}={0,2}"), "Bearer [redacted]"),
    (
        re.compile(r"(?i)\b(?:api[_-]?key|GEMINI_API_KEY)\s*[:=]\s*\S+"),
        "api_key=[redacted]",
    ),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{10,}"), "[redacted-google-key]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{10,}"), "[redacted-sk]"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "[redacted-private-key]"),
    (re.compile(r"(?i)\bpassword\s*[:=]\s*\S{4,}"), "password=[redacted]"),
    (
        re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|redis|mysql)://\S+"),
        "[redacted-db-url]",
    ),
    (re.compile(r"(?i)\bCookie\s*:\s*\S+"), "Cookie: [redacted]"),
    (
        re.compile(r"(?i)firebase[\w\s]{0,40}(secret|private_key|token|key\.json)"),
        "firebase [redacted]",
    ),
)

_CODE_PATTERN = re.compile(r"\b(?:error\s+)?(4\d{2}|5\d{2})\b", re.IGNORECASE)

_RETRYABLE_CODES = frozenset({408, 429, 500, 502, 503, 504})
_NON_RETRYABLE_CODES = frozenset({400, 401, 403, 404})


def _redact(text: str) -> str:
    redacted = text
    for pattern, replacement in _REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _extract_code(exc: BaseException, message: str) -> str:
    for attr in ("code", "status_code", "status", "http_status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value <= 599:
            return str(value)
        if isinstance(value, str) and value.isdigit():
            code = int(value)
            if 100 <= code <= 599:
                return str(code)
    match = _CODE_PATTERN.search(message)
    if match:
        return match.group(1)
    return "unknown"


def _classify_retryable(code: str, message: str) -> str:
    lowered = message.lower()
    if "timeout" in lowered or "timed out" in lowered:
        return "yes"
    if code.isdigit():
        numeric = int(code)
        if numeric in _RETRYABLE_CODES:
            return "yes"
        if numeric in _NON_RETRYABLE_CODES:
            return "no"
    if any(
        marker in lowered
        for marker in ("rate limit", "rate_limit", "quota", "overloaded", "unavailable")
    ):
        return "yes"
    if any(
        marker in lowered
        for marker in ("not found", "not-found", "invalid", "unauthorized", "forbidden")
    ):
        return "no"
    return "unknown"


def sanitize_provider_error(exc: BaseException, *, max_chars: int = 500) -> str:
    """One-line redacted diagnostic for a provider-call failure."""
    name = type(exc).__name__
    try:
        raw_message = str(exc)
    except Exception:  # noqa: BLE001 - diagnostic must never raise
        raw_message = ""
    if not raw_message and exc.args:
        try:
            raw_message = str(exc.args[0])[:2000]
        except Exception:  # noqa: BLE001 - diagnostic must never raise
            raw_message = ""
    message = _redact(raw_message.strip().replace("\n", " "))
    if not message:
        message = "no detail"
    code = _extract_code(exc, raw_message)
    retryable = _classify_retryable(code, raw_message)
    diagnostic = f"{name} | code={code} | retryable={retryable} | msg={message}"
    return diagnostic[:max_chars]


__all__ = ["MAX_DIAGNOSTIC_CHARS", "sanitize_provider_error"]

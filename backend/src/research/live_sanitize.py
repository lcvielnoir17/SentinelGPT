"""Output sanitization for live transcripts (M19, fail-closed).

Every provider reply is scanned for credential-like material BEFORE
storage. A hit rejects the transcript (recorded as
``rejected_sanitization`` — the raw text is never persisted). Patterns
are tight by design: ordinary security prose ("recovery", "password
policy", CVE discussion) must pass; only credential-shaped material
fails. The scanner itself is pure and dependency-free.
"""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
    ("api-key-prefix", re.compile(r"\bsk-[A-Za-z0-9]{10,}")),
    ("google-key-prefix", re.compile(r"\bAIza[0-9A-Za-z_-]{10,}")),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{10,}={0,2}")),
    ("password-assignment", re.compile(r"(?i)\bpassword\s*[:=]\s*\S{4,}")),
    ("db-url", re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|redis|mysql)://\S+")),
    ("cookie-header", re.compile(r"(?i)\bCookie\s*:\s*\S+")),
    (
        "firebase-secret",
        re.compile(r"(?i)firebase[\w\s]{0,40}(secret|private_key|token|key\.json)"),
    ),
)

MAX_RESPONSE_CHARS = 131_072


def scan_response(text: str) -> list[str]:
    """Credential-pattern hits in provider output (empty = storable)."""
    if not isinstance(text, str):
        return ["non-text response"]
    if len(text) > MAX_RESPONSE_CHARS:
        return ["oversized response"]
    return [name for name, pattern in _PATTERNS if pattern.search(text)]


__all__ = ["MAX_RESPONSE_CHARS", "scan_response"]

"""TOTP (RFC 4226/6238) over the standard library only (M11).

No new cryptography is invented here: HMAC-SHA1 truncation is the RFC
construction, implemented with :mod:`hmac`, :mod:`hashlib`, and
:mod:`struct`. The module proves itself against the RFC 6238 Appendix
B vectors in the unit suite — the same guarantee a vendored library
would carry, without lockfile churn.

Parameters: 20-byte secret, 30-second step, 6 digits, SHA-1, ±1 step
verification window (clock skew tolerance).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import UTC, datetime

TIME_STEP_SECONDS = 30
CODE_DIGITS = 6
SECRET_BYTES = 20
ALLOWED_SKEW_STEPS = 1


def generate_secret() -> str:
    """Fresh 160-bit secret, base32 without padding (authenticator-ready)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def code_at(secret_base32: str, moment: datetime) -> str:
    """The TOTP code for one instant (single step, no window)."""
    key = _decode_secret(secret_base32)
    counter = int(moment.timestamp()) // TIME_STEP_SECONDS
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**CODE_DIGITS)).zfill(CODE_DIGITS)


def verify_code(secret_base32: str, code: str, now: datetime | None = None) -> bool:
    """Constant-time check across the skew window (malformed never matches)."""
    return matching_step(secret_base32, code, now) is not None


def matching_step(secret_base32: str, code: str, now: datetime | None = None) -> int | None:
    """Matched time-step counter, or None (drives single-use consumption)."""
    if not isinstance(code, str) or len(code) != CODE_DIGITS or not code.isdigit():
        return None
    try:
        key = _decode_secret(secret_base32)
    except ValueError:
        return None
    moment = now if now is not None else datetime.now(UTC)
    base = int(moment.timestamp()) // TIME_STEP_SECONDS
    for step in range(-ALLOWED_SKEW_STEPS, ALLOWED_SKEW_STEPS + 1):
        message = struct.pack(">Q", base + step)
        digest = hmac.new(key, message, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        candidate = str(truncated % (10**CODE_DIGITS)).zfill(CODE_DIGITS)
        if hmac.compare_digest(candidate, code):
            return base + step
    return None


def provisioning_uri(secret_base32: str, *, account: str, issuer: str = "SentinelGPT") -> str:
    """otpauth:// URI for QR provisioning (contains the secret — show once)."""
    from urllib.parse import quote

    label = f"{quote(issuer)}:{quote(account)}"
    params = f"secret={secret_base32}&issuer={quote(issuer)}&digits=6&period=30"
    return f"otpauth://totp/{label}?{params}"


def _decode_secret(secret_base32: str) -> bytes:
    """Base32 with or without padding (authenticator apps omit it)."""
    normalized = secret_base32.strip().upper()
    padding = "=" * (-len(normalized) % 8)
    try:
        return base64.b32decode(normalized + padding)
    except Exception as exc:
        raise ValueError("not base32") from exc


def current_code(secret_base32: str) -> str:
    """Current code (tests and enrollment UX helpers only)."""
    return code_at(secret_base32, datetime.now(UTC))


__all__ = [
    "ALLOWED_SKEW_STEPS",
    "CODE_DIGITS",
    "TIME_STEP_SECONDS",
    "code_at",
    "current_code",
    "generate_secret",
    "matching_step",
    "provisioning_uri",
    "verify_code",
]

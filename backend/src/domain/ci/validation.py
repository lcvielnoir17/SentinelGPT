"""CI input validation: names, idempotency keys, expirations (M10).

Pure, network-free validation. Failures raise
:class:`InvalidCiError` (400) directly so services stay thin.
"""

from __future__ import annotations

import string
import uuid
from datetime import UTC, datetime

from src.domain.ci.errors import InvalidCiError

MAX_NAME_CHARS = 100
MAX_KEY_CHARS = 128
_KEY_ALPHABET = frozenset(string.ascii_letters + string.digits + "-_")

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def parse_name(raw: object) -> str:
    """Credential display name (1..100 chars, trimmed)."""
    if not isinstance(raw, str):
        raise InvalidCiError("name must be text.")
    name = raw.strip()
    if not name or len(name) > MAX_NAME_CHARS:
        raise InvalidCiError("name must be 1..100 characters.")
    if "\x00" in name:
        raise InvalidCiError("name must not contain null bytes.")
    return name


def parse_uuid(raw: object, field: str) -> uuid.UUID:
    """Strict UUID field (credential ids, target ids, scan ids)."""
    if not isinstance(raw, str):
        raise InvalidCiError(f"{field} must be a UUID string.")
    try:
        return uuid.UUID(raw.strip())
    except (ValueError, AttributeError) as exc:
        raise InvalidCiError(f"{field} must be a UUID string.") from exc


def parse_idempotency_key(raw: object) -> str | None:
    """Optional retry key: absent/None means 'no idempotency requested'.

    Keys are opaque client-chosen strings (1..128 chars over
    ``[A-Za-z0-9_-]``) — deterministic by construction, never derived
    from timestamps.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise InvalidCiError("idempotencyKey must be text or null.")
    key = raw.strip()
    if not key:
        return None
    if len(key) > MAX_KEY_CHARS or any(c not in _KEY_ALPHABET for c in key):
        raise InvalidCiError("idempotencyKey must be 1..128 chars over [A-Za-z0-9_-].")
    return key


def parse_expires_at(raw: object) -> datetime | None:
    """Optional tz-aware future expiration (naive datetimes rejected).

    Naive datetimes are rejected rather than silently assumed UTC —
    the M8 due-date convention.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise InvalidCiError("expiresAt must be an ISO-8601 datetime string or null.")
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise InvalidCiError("expiresAt must be an ISO-8601 datetime string.") from exc
    if parsed.tzinfo is None:
        raise InvalidCiError("expiresAt must carry timezone information.")
    moment = parsed.astimezone(UTC)
    if moment <= datetime.now(UTC):
        raise InvalidCiError("expiresAt must be in the future.")
    return moment


def parse_scan_profile(raw: object) -> str:
    """Optional scan profile code (defaults to standard; validated later)."""
    if raw is None:
        return "standard"
    if not isinstance(raw, str) or not raw.strip() or len(raw.strip()) > 50:
        raise InvalidCiError("scanProfile must be text (max 50 chars) or null.")
    return raw.strip()


__all__ = [
    "MAX_KEY_CHARS",
    "MAX_NAME_CHARS",
    "SEVERITIES",
    "parse_expires_at",
    "parse_idempotency_key",
    "parse_name",
    "parse_scan_profile",
    "parse_uuid",
]

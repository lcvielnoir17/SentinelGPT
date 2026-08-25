"""Access-token signing/verification for cookie-based authentication.

Implements the access-token half of the SRS Chapter 2 Section 9 invariant
(short-lived signed JWT delivered only as an HttpOnly/Secure/SameSite=Strict
cookie). Refresh-token issuance, rotation, reuse detection, MFA, and logout
remain Phase 1 Auth Service deliverables and intentionally live elsewhere.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt

from src.domain.errors import NotAuthenticatedError


def create_access_token(
    *,
    user_id: uuid.UUID,
    secret_key: str,
    algorithm: str,
    expires_in_minutes: int,
) -> str:
    """Sign a short-lived access JWT whose ``sub`` claim is the user id."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=expires_in_minutes),
    }
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_access_token(
    token: str,
    *,
    secret_key: str,
    algorithm: str,
) -> uuid.UUID:
    """Verify signature/expiry and return the authenticated user id.

    Any failure (malformed, tampered, expired) raises NotAuthenticatedError —
    mapped to 401 UNAUTHENTICATED by the centralized error handlers.
    """
    try:
        claims = jwt.decode(
            token,
            secret_key,
            algorithms=[algorithm],
            options={"require": ["sub", "exp"]},
        )
    except jwt.PyJWTError as exc:
        raise NotAuthenticatedError() from exc
    try:
        return uuid.UUID(str(claims["sub"]))
    except (ValueError, KeyError) as exc:
        raise NotAuthenticatedError() from exc

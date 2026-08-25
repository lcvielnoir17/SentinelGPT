"""Refresh-token lifecycle: issuance, rotation, reuse detection, revocation.

Implements the refresh/session half of SRS Chapter 2 Section 9, Chapter 5
Section 2, and Chapter 11 Section 8:

* Refresh credentials are opaque CSPRNG strings delivered only as an
  HttpOnly/Secure/SameSite=Strict cookie scoped to the auth routes; only their
  SHA-256 hashes are persisted (the raw secret never touches the database).
* Every refresh performs true rotation: the presented row becomes ROTATED and
  a new child credential is created within the same ``family_id``.
* Presenting a rotated-out credential is reuse: the ENTIRE family is revoked
  (Chapter 5 Section 2) and the caller answers 401.
* Logout revokes the presented session; repeat logouts are idempotent.

Transactional contract: ``refresh`` NEVER raises for domain rejections. It
stages security transitions (revocations/rotation) as ordinary ORM work and
reports the outcome; the route persists those transitions (commit) BEFORE
raising NotAuthenticatedError, because the shared request-scoped session rolls
back on any exception — a raise-first design would silently undo reuse-family
revocation. Rotation uses an atomic conditional UPDATE so concurrent requests
can never produce two live descendants from one credential.

Access tokens remain short-lived JWTs (token_service.py) and are structurally
separate: opaque refresh credentials can never decode as access JWTs and an
access JWT hashes to no known session row.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from src.infrastructure.database.models.refresh_session_models import (
    SESSION_ACTIVE,
    SESSION_REVOKED,
    SESSION_ROTATED,
    RefreshSession,
)
from src.infrastructure.database.repositories.refresh_session_repository import (
    RefreshSessionRepository,
)
from src.infrastructure.database.repositories.user_repository import UserRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

RAW_REFRESH_TOKEN_BYTES = 48


class RefreshRejection(StrEnum):
    """Why a refresh/logout-adjacent validation failed."""

    UNKNOWN = "unknown"
    EXPIRED = "expired"
    INACTIVE_USER = "inactive_user"
    REUSED = "reused"


@dataclass(frozen=True)
class RotatedSession:
    """The new child credential produced by a successful rotation."""

    user_id: uuid.UUID
    family_id: uuid.UUID
    raw_token: str
    expires_at: datetime


@dataclass(frozen=True)
class RefreshOutcome:
    """Result of a refresh attempt: either rotated or rejected-with-reason."""

    rotated: RotatedSession | None
    rejection: RefreshRejection | None


def generate_raw_refresh_token() -> str:
    """CSPRNG opaque credential; only its hash ever touches the database."""
    return secrets.token_urlsafe(RAW_REFRESH_TOKEN_BYTES)


def hash_refresh_token(raw_token: str) -> str:
    """Deterministic lookup key for a raw credential (SHA-256 hex)."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _rejected(rejection: RefreshRejection) -> RefreshOutcome:
    return RefreshOutcome(rotated=None, rejection=rejection)


class RefreshService:
    """Business rules for refresh-token sessions."""

    def __init__(self, session: AsyncSession, refresh_ttl_days: int) -> None:
        self._repository = RefreshSessionRepository(session)
        self._users = UserRepository(session)
        self._refresh_ttl_days = refresh_ttl_days

    def issue_family(self, user_id: uuid.UUID) -> tuple[str, datetime]:
        """Create the first credential of a new family (login). Raw + expiry."""
        raw = generate_raw_refresh_token()
        expires_at = datetime.now(UTC) + timedelta(days=self._refresh_ttl_days)
        self._repository.add(
            RefreshSession(
                user_id=user_id,
                family_id=uuid.uuid4(),
                token_hash=hash_refresh_token(raw),
                status=SESSION_ACTIVE,
                expires_at=expires_at,
            )
        )
        return raw, expires_at

    async def refresh(self, raw_token: str | None) -> RefreshOutcome:
        """Validate one credential and rotate it, enforcing reuse detection."""
        if not raw_token:
            return _rejected(RefreshRejection.UNKNOWN)
        stored = await self._repository.get_by_token_hash(hash_refresh_token(raw_token))
        if stored is None or stored.status == SESSION_REVOKED:
            return _rejected(RefreshRejection.UNKNOWN)

        # Reuse of a rotated-out credential: kill the entire family (Ch5 §2).
        if stored.status == SESSION_ROTATED:
            await self._repository.revoke_family(stored.family_id)
            return _rejected(RefreshRejection.REUSED)

        if _is_expired(stored.expires_at):
            await self._repository.revoke(stored.id)
            return _rejected(RefreshRejection.EXPIRED)

        # The account must still be eligible to authenticate (no bypass of
        # deactivation through refresh).
        user = await self._users.get_by_id(stored.user_id)
        if user is None or not user.is_active:
            await self._repository.revoke(stored.id)
            return _rejected(RefreshRejection.INACTIVE_USER)

        # Atomic ACTIVE->ROTATED: a concurrent loser must not create a second
        # live descendant; losing the race is treated exactly like reuse.
        if not await self._repository.try_mark_rotated(stored.id):
            await self._repository.revoke_family(stored.family_id)
            return _rejected(RefreshRejection.REUSED)

        raw = generate_raw_refresh_token()
        expires_at = datetime.now(UTC) + timedelta(days=self._refresh_ttl_days)
        self._repository.add(
            RefreshSession(
                user_id=stored.user_id,
                family_id=stored.family_id,
                token_hash=hash_refresh_token(raw),
                status=SESSION_ACTIVE,
                expires_at=expires_at,
            )
        )
        return RefreshOutcome(
            rotated=RotatedSession(
                user_id=stored.user_id,
                family_id=stored.family_id,
                raw_token=raw,
                expires_at=expires_at,
            ),
            rejection=None,
        )

    async def logout(self, raw_token: str | None) -> None:
        """Revoke the presented ACTIVE credential if present; idempotent.

        Runs without raising so commit-on-success persists the revocation;
        unknown/already-revoked credentials are accepted silently (repeat
        logout must not fail and must not leak session existence).
        """
        if not raw_token:
            return
        stored = await self._repository.get_by_token_hash(hash_refresh_token(raw_token))
        if stored is not None and stored.status == SESSION_ACTIVE:
            await self._repository.revoke(stored.id)


def _is_expired(expires_at: datetime) -> bool:
    return expires_at <= datetime.now(UTC)

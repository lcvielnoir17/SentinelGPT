"""User domain service: registration and credential authentication.

PHASE 0 SCOPE (SRS Chapter 15, Section 2): this service implements *real*
credential storage and verification (Argon2id hashes persisted to the ``user``
table) so the Phase 0 exit criterion works end-to-end. Token issuance,
refresh-token rotation, MFA, lockout, and HttpOnly cookie delivery are Phase 1
deliverables (Chapter 15, Section 3 / Chapter 11, Section 8) and are
intentionally absent here — nothing in this module pretends to issue sessions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.domain.errors import EmailAlreadyRegisteredError, InvalidCredentialsError
from src.domain.users.password_hasher import hash_password, verify_password
from src.infrastructure.database.models import User
from src.infrastructure.database.repositories.user_repository import UserRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# Temporary Phase 0 baseline password policy. Phase 1 replaces this with the
# full Auth Service policy enforcement (SRS Chapter 2, Section 9).
MIN_PASSWORD_LENGTH = 12


@dataclass(frozen=True)
class UserAccount:
    """Framework-agnostic user entity returned by domain services."""

    id: uuid.UUID
    email: str
    created_at: datetime


class UserService:
    """Business rules for user registration and login."""

    def __init__(self, session: AsyncSession) -> None:
        self._repository = UserRepository(session)

    async def register_user(self, email: str, password: str) -> UserAccount:
        """Create a new account; raises on duplicate email."""
        existing = await self._repository.get_by_email(email)
        if existing is not None:
            raise EmailAlreadyRegisteredError()

        # Identity fields are assigned here (not left to flush-time defaults)
        # so the returned entity is complete without a DB round-trip; the
        # schema's server_default remains the authority for non-ORM writes.
        now = datetime.now(UTC)
        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password(password),
            created_at=now,
            updated_at=now,
        )
        self._repository.add(user)
        await self._repository.flush()
        return UserAccount(id=user.id, email=user.email, created_at=user.created_at)

    async def authenticate(self, email: str, password: str) -> UserAccount:
        """Verify credentials; raises InvalidCredentialsError on any failure."""
        user = await self._repository.get_by_email(email)
        # Identical failure path for unknown-email vs wrong-password: no
        # enumeration oracle (SRS Chapter 5, Section 2).
        if user is None or not verify_password(user.password_hash, password) or not user.is_active:
            raise InvalidCredentialsError()
        return UserAccount(id=user.id, email=user.email, created_at=user.created_at)

    async def get_account(self, user_id: uuid.UUID) -> UserAccount | None:
        """Load an account by id (used post-rotation to build the response)."""
        user = await self._repository.get_by_id(user_id)
        if user is None:
            return None
        return UserAccount(id=user.id, email=user.email, created_at=user.created_at)

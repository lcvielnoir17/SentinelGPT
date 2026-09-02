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

    from src.domain.users.firebase_token_service import FirebaseIdentity

# Temporary Phase 0 baseline password policy. Phase 1 replaces this with the
# full Auth Service policy enforcement (SRS Chapter 2, Section 9).
MIN_PASSWORD_LENGTH = 12


@dataclass(frozen=True)
class UserAccount:
    """Framework-agnostic user entity returned by domain services."""

    id: uuid.UUID
    email: str
    created_at: datetime
    # Present only for federated logins (ADR-0010); the canonical identity
    # remains ``id`` — Firestore paths and authorization always key on it.
    firebase_uid: str | None = None


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
        return self._to_account(user)

    async def authenticate(self, email: str, password: str) -> UserAccount:
        """Verify credentials; raises InvalidCredentialsError on any failure."""
        user = await self._repository.get_by_email(email)
        # Identical failure path for unknown-email vs wrong-password vs
        # federated-only account (no local password): no enumeration oracle
        # (SRS Chapter 5, Section 2).
        if user is None or user.password_hash is None:
            raise InvalidCredentialsError()
        if not verify_password(user.password_hash, password) or not user.is_active:
            raise InvalidCredentialsError()
        return self._to_account(user)

    async def authenticate_firebase(
        self, identity: FirebaseIdentity, *, project_id: str = "unknown-project"
    ) -> UserAccount:
        """Resolve or provision the canonical account for a verified identity.

        Mapping policy (ADR-0010):
        1. ``firebase_uid`` match wins — that account IS the identity.
        2. Otherwise, link the existing local account with the same email
           ONLY when Firebase asserts the address is verified; this can
           never be forged by an attacker controlling an unverified
           Firebase email.
        3. Otherwise provision a new federated account (no local password).
           An unverified or absent email is untrusted, so the account gets
           a deterministic synthetic address until Firebase verifies.

        The resulting account is the single source of authorization for
        every downstream request; the Firebase UID is only the login bridge.
        """
        user = await self._repository.get_by_firebase_uid(identity.uid)

        if user is None and identity.email and identity.email_verified:
            candidate = await self._repository.get_by_email(identity.email)
            if candidate is not None and candidate.firebase_uid is None:
                # Verified-email linkage. Guard the non-federated invariant:
                # a local password account keeps its password and gains a
                # second login path.
                self._repository.link_firebase_uid(candidate, identity.uid)
                user = candidate

        if user is None:
            email = (
                identity.email
                if identity.email and identity.email_verified
                else self._synthetic_firebase_email(identity.uid, project_id)
            )
            if email == identity.email:
                # Firebase guarantees per-project email uniqueness, but a
                # concurrent/raced provision must never attempt a duplicate
                # insert (unique constraint). Anything already owning the
                # address means the bridge cannot establish this identity.
                owner = await self._repository.get_by_email(identity.email)
                if owner is not None:
                    raise InvalidCredentialsError()
            now = datetime.now(UTC)
            user = User(
                id=uuid.uuid4(),
                email=email,
                password_hash=None,
                firebase_uid=identity.uid,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            self._repository.add(user)
            await self._repository.flush()

        if not user.is_active:
            raise InvalidCredentialsError()

        # Firebase may assert a newer verified address; keep the local
        # account consistent unless another account already owns it.
        if identity.email and identity.email_verified and user.email != identity.email:
            owner = await self._repository.get_by_email(identity.email)
            if owner is None:
                user.email = identity.email

        return self._to_account(user)

    def _synthetic_firebase_email(self, uid: str, project_id: str) -> str:
        """Deterministic placeholder for federated identities without a
        verified email. ``users.firebase.<project-id>`` is a valid domain
        (Firebase project IDs are DNS names) accepted by the API's
        EmailStr validation."""
        return f"{uid}@users.firebase.{project_id}"

    def _to_account(self, user: User) -> UserAccount:
        return UserAccount(
            id=user.id,
            email=user.email,
            created_at=user.created_at,
            firebase_uid=user.firebase_uid,
        )

    async def get_account(self, user_id: uuid.UUID) -> UserAccount | None:
        """Load an account by id (used post-rotation to build the response)."""
        user = await self._repository.get_by_id(user_id)
        if user is None:
            return None
        return self._to_account(user)

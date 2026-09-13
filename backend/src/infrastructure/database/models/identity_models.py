"""Core identity models: user account.

Implements SRS Chapter 4, Section 4.1 exactly (types, constraints,
cascade policy). Organization-based multi-tenancy was removed:
every target is owned directly by its registering user.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base


def _utc_now() -> datetime:
    """Python-side UTC default so entities are complete before flush."""
    return datetime.now(UTC)


class User(Base):
    """Platform user account (SRS Chapter 4, Section 4.1)."""

    __tablename__ = "user"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Argon2id hash (Phase 0 registration/login path); never stores plaintext.
    # Nullable since ADR-0010: federated (Firebase) accounts have no local
    # password and can never authenticate via POST /auth/login.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Verified Firebase UID recorded by the /auth/firebase ID-token exchange
    # (ADR-0010). Uniqueness for non-NULL values is enforced by a partial
    # unique index (migration 0007).
    firebase_uid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        onupdate=func.now(),
        server_default=func.now(),
        nullable=False,
    )

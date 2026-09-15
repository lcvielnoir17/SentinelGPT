"""MFA persistence models: one-time recovery codes (M11), TOTP replay guard.

The TOTP secret itself lives on the existing ``user`` columns
(``mfa_enabled``, ``mfa_secret_encrypted``) — no identity duplication.
Recovery codes need per-code one-time state, so they get their own
table: only hashes persist, use is recorded, and codes are never
updated (consumed rows stay as spent history).
TOTP codes are single-use per time step via ``mfa_totp_use``: the
unique (user, step) row makes a replayed code fail closed, and rows
older than the skew window are pruned opportunistically.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class MfaRecoveryCode(Base):
    """One hashed single-use recovery code for a user (M11)."""

    __tablename__ = "mfa_recovery_code"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )


class MfaTotpUse(Base):
    """One consumed TOTP time step for a user (replay guard).

    Only the step counter persists — never the code — so the table
    proves freshness without storing anything an attacker could reuse.
    """

    __tablename__ = "mfa_totp_use"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    time_step: Mapped[int] = mapped_column(BigInteger, nullable=False)
    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )

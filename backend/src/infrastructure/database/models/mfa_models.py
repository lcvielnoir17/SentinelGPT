"""MFA persistence models: one-time recovery codes (M11).

The TOTP secret itself lives on the existing ``user`` columns
(``mfa_enabled``, ``mfa_secret_encrypted``) — no identity duplication.
Recovery codes need per-code one-time state, so they get their own
table: only hashes persist, use is recorded, and codes are never
updated (consumed rows stay as spent history).
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, func
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

"""Refresh-token session store (SRS Chapter 11 Section 8 / Chapter 2 Section 9).

One row per issued refresh credential. Raw refresh credentials are never
persisted — only their SHA-256 hashes. Rotation marks the presented row
ROTATED and issues a child row sharing its ``family_id``; presenting any
ROTATED row again is reuse and revokes the whole family (Chapter 5 Section 2).
ON DELETE RESTRICT follows Chapter 4 Section 13's cascade policy (CASCADE is
reserved for membership-style join records); sessions are checked against
``user.is_active`` on every use instead.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base

SESSION_ACTIVE = "ACTIVE"
SESSION_ROTATED = "ROTATED"
SESSION_REVOKED = "REVOKED"


def _utc_now() -> datetime:
    """Python-side UTC default so entities are complete before flush."""
    return datetime.now(UTC)


class RefreshSession(Base):
    """A single issued refresh credential within a rotation family."""

    __tablename__ = "refresh_session"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_refresh_session_token_hash"),
        CheckConstraint(
            f"status IN ('{SESSION_ACTIVE}', '{SESSION_ROTATED}', '{SESSION_REVOKED}')",
            name="status_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    # Owning account; every refresh re-verifies user.is_active server-side.
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # All descendants of one login share this id — the revocation unit for
    # reuse detection (Chapter 5 Section 2: "revokes the entire token family").
    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    # SHA-256 hex digest of the opaque raw credential (64 chars). The raw
    # secret is delivered only via the HttpOnly cookie and never stored.
    token_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )

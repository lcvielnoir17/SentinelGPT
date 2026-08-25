"""Target model (SRS Chapter 4, Section 4.4).

A target belongs to exactly one owning entity — an organization or an
individual user — enforced by the ``single_owner`` check constraint. The
unique constraint on (owner_organization_id, owner_user_id, normalized_url)
prevents duplicate registration within the same owning entity;
``postgresql_nulls_not_distinct`` makes the NULL owner column participate in
uniqueness so personal targets cannot be duplicated either.
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


def _utc_now() -> datetime:
    """Python-side UTC default so entities are complete before flush."""
    return datetime.now(UTC)


class Target(Base):
    """A scannable asset registered by its owning entity (Ch. 4 §4.4)."""

    __tablename__ = "target"
    __table_args__ = (
        UniqueConstraint(
            "owner_organization_id",
            "owner_user_id",
            "normalized_url",
            name="uq_target_owner_url",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint(
            "(owner_organization_id IS NULL) != (owner_user_id IS NULL)",
            name="single_owner",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    owner_organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organization.id", ondelete="RESTRICT"),
        nullable=True,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=True,
    )
    hostname: Mapped[str] = mapped_column(String(255))
    # Canonicalized form used for SSRF-safe resolution (Chapter 2/3).
    normalized_url: Mapped[str] = mapped_column(String(500))
    # Soft-delete pattern: historical scans remain valid after archival.
    is_archived: Mapped[bool] = mapped_column(default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )

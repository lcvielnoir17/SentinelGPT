"""Target model (SRS Chapter 4, Section 4.4).

A target is owned directly by the user who registered it. The unique
constraint on (owner_user_id, normalized_url) prevents duplicate
registration by the same owner.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
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
    """A scannable asset registered by its owning user (Ch. 4 §4.4)."""

    __tablename__ = "target"
    __table_args__ = (
        UniqueConstraint(
            "owner_user_id",
            "normalized_url",
            name="uq_target_owner_url",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
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


class TargetTechnology(Base):
    """Detected asset technology bound to a target (observation inventory).

    One row per (target, technology slug); rescans upsert in place, so the
    row always describes the latest observation while ``first_observed_at``
    preserves provenance. This table NEVER creates vulnerabilities: it feeds
    the v2 priority technology-relevance signal (only with paired
    CVE/CVSS enrichment) and future asset-context views.
    """

    __tablename__ = "target_technology"
    __table_args__ = (
        UniqueConstraint(
            "target_id",
            "slug",
            name="uq_target_technology_identity",
        ),
        CheckConstraint(
            "family IN ('server', 'framework', 'language', 'cms', 'proxy')",
            name="ck_technology_family",
        ),
        CheckConstraint(
            "confidence IN ('HIGH', 'MEDIUM', 'LOW')",
            name="ck_technology_confidence",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("target.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    display: Mapped[str] = mapped_column(String(100), nullable=False)
    family: Mapped[str] = mapped_column(String(20), nullable=False)
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    sources: Mapped[str] = mapped_column(Text, nullable=False, default="")
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )
    observed_in_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )

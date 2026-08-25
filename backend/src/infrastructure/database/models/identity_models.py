"""Core identity models: user, organization, organization_membership.

Implements SRS Chapter 4, Sections 4.1-4.3 exactly (types, constraints,
cascade policy).
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.infrastructure.database.models.base import Base

ROLE_ADMIN: str = "ADMIN"
ROLE_MEMBER: str = "MEMBER"


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
    password_hash: Mapped[str] = mapped_column(String(255))
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

    memberships: Mapped[list["OrganizationMembership"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Organization(Base):
    """Tenant boundary for targets/scans (SRS Chapter 4, Section 4.2)."""

    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255))
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

    memberships: Mapped[list["OrganizationMembership"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class OrganizationMembership(Base):
    """Join record binding a user to an organization with an access role.

    Role taxonomy intentionally minimal (ADMIN|MEMBER check constraint, not a
    lookup table) per SRS Chapter 4, Section 4.3. ON DELETE CASCADE applies
    here as the one sanctioned cascade case in Chapter 4, Section 13.
    """

    __tablename__ = "organization_membership"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_membership_org_user"),
        CheckConstraint(
            f"role IN ('{ROLE_ADMIN}', '{ROLE_MEMBER}')",
            name="role_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organization.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
    )

    organization: Mapped["Organization"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship(back_populates="memberships")

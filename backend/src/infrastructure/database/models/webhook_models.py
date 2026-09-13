"""Webhook subscription and delivery models (event notifications).

A webhook belongs to exactly one owner and subscribes to deterministic
domain event types. Delivery rows are the idempotency ledger: one row
per (webhook, event) enforced by a unique constraint, so retries,
restarts, and duplicate fanouts can never double-deliver.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Webhook(Base):
    """One owner's event subscription (secret stored encrypted)."""

    __tablename__ = "webhook"
    __table_args__ = (
        CheckConstraint(
            "timeout_seconds >= 5 AND timeout_seconds <= 60",
            name="ck_webhook_timeout",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    events: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10, server_default="10")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        onupdate=func.now(),
        server_default=func.now(),
        nullable=False,
    )


class WebhookDelivery(Base):
    """One delivery attempt ledger row (idempotency: webhook × event)."""

    __tablename__ = "webhook_delivery"
    __table_args__ = (
        UniqueConstraint(
            "webhook_id",
            "event_id",
            name="uq_webhook_delivery_identity",
        ),
        CheckConstraint(
            "status IN ('pending', 'sent', 'failed', 'cancelled')",
            name="ck_delivery_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("webhook.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    event_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        onupdate=func.now(),
        server_default=func.now(),
        nullable=False,
    )

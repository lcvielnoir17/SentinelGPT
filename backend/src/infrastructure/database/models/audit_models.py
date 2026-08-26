"""Append-only audit log (SRS Chapter 4, Section 10.1; Chapter 11).

Integrity model (Ch. 4 §10): the strongest guarantee available to survive
even a bug in application code. Implemented as a BEFORE UPDATE OR DELETE
trigger that raises, applied by migration 0005 — the table is physically
append-only regardless of database role. Repository exposes insert/query
only; no update/delete path exists in application code either.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLogEntry(Base):
    """INSERT-only audit record (SRS Chapter 4, Section 10.1)."""

    __tablename__ = "audit_log_entry"
    __table_args__ = (Index("ix_audit_entity", "entity_type", "entity_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user.id", ondelete="RESTRICT"), nullable=True
    )
    action_code: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )

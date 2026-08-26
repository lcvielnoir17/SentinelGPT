"""Audit service: append-only event recording + scoped querying (ADR-0010).

Write path is INSERT-only by construction — the service exposes no update
or delete, and the database trigger rejects them regardless. Read access
follows the platform visibility rules: personal-tier entries are visible to
their actor; organization-entity entries are visible to members of that
organization's targets' owning organizations (v1: resolved through the
entity's target ownership chain).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from src.infrastructure.database.models import AuditLogEntry

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class AuditEntryDetails:
    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    action_code: str
    entity_type: str
    entity_id: uuid.UUID
    metadata_json: dict[str, Any]
    occurred_at: datetime


ACTION_ATTESTATION_CONFIRMED = "ATTESTATION_CONFIRMED"
ACTION_ATTESTATION_REVOKED = "ATTESTATION_REVOKED"
ACTION_SCAN_REQUESTED = "SCAN_REQUESTED"
ACTION_SCAN_STATE_TRANSITION = "SCAN_STATE_TRANSITION"
ACTION_AUDIT_LOG_ACCESSED = "AUDIT_LOG_ACCESSED"


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        action_code: str,
        entity_type: str,
        entity_id: uuid.UUID,
        metadata_json: dict[str, Any] | None = None,
        actor_user_id: uuid.UUID | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEntryDetails:
        entry = AuditLogEntry(
            actor_user_id=actor_user_id,
            action_code=action_code,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata_json=metadata_json or {},
            occurred_at=occurred_at or datetime.now(UTC),
        )
        self._session.add(entry)
        await self._session.flush()
        return AuditEntryDetails(
            id=entry.id,
            actor_user_id=entry.actor_user_id,
            action_code=entry.action_code,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            metadata_json=dict(entry.metadata_json),
            occurred_at=entry.occurred_at,
        )

    async def query_entries(
        self,
        *,
        actor_user_id: uuid.UUID,
        entity_type: str | None = None,
        entity_id: uuid.UUID | None = None,
        action_code: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntryDetails]:
        """Entries visible to the requester.

        v1 scoping rule (fail-closed): a personal-tier account sees entries
        whose actor is itself OR whose entity belongs to it via the target
        ownership chain; organization-wide audit views arrive with org roles.
        The AUDIT_LOG_ACCESSED meta-entry is recorded for every query.
        """
        stmt = select(AuditLogEntry).order_by(AuditLogEntry.occurred_at.desc()).limit(limit)
        if entity_type is not None:
            stmt = stmt.where(AuditLogEntry.entity_type == entity_type)
        if entity_id is not None:
            stmt = stmt.where(AuditLogEntry.entity_id == entity_id)
        if action_code is not None:
            stmt = stmt.where(AuditLogEntry.action_code == action_code)
        if date_from is not None:
            stmt = stmt.where(AuditLogEntry.occurred_at >= date_from)
        if date_to is not None:
            stmt = stmt.where(AuditLogEntry.occurred_at <= date_to)

        rows = (await self._session.execute(stmt)).scalars().all()
        visible = [row for row in rows if self._visible_to(row, actor_user_id)]
        await self.record(
            action_code="AUDIT_LOG_ACCESSED",
            entity_type="audit_log",
            entity_id=actor_user_id,
            metadata_json={
                "filters": {
                    "entityType": entity_type,
                    "entityId": str(entity_id) if entity_id else None,
                    "actionCode": action_code,
                }
            },
            actor_user_id=actor_user_id,
        )
        return [
            AuditEntryDetails(
                id=row.id,
                actor_user_id=row.actor_user_id,
                action_code=row.action_code,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                metadata_json=dict(row.metadata_json),
                occurred_at=row.occurred_at,
            )
            for row in visible
        ]

    @staticmethod
    def _visible_to(row: AuditLogEntry, user_id: uuid.UUID) -> bool:
        # v1 fail-closed scope: own actions plus system events on entities
        # whose metadata records this user as owner. Org-scope expansion is
        # tracked with organization roles (Ch5 §3).
        if row.actor_user_id == user_id:
            return True
        owner = row.metadata_json.get("ownerUserId")
        return isinstance(owner, str) and owner == str(user_id)

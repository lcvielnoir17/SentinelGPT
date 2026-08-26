"""Audit log query endpoints (SRS Chapter 5, Section 12; Chapter 4 §10).

Access: personal-tier entries are visible to their actor (v1 fail-closed
scoping in AuditService; org-ADMIN views arrive with org roles). Per the
Chapter 5 §12 meta-audit note, every query records an AUDIT_LOG_ACCESSED
entry.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import CurrentUser  # noqa: TC001 - FastAPI runtime
from src.domain.audit.audit_service import AuditEntryDetails, AuditService
from src.infrastructure.database.connection import get_db_session

router = APIRouter(prefix="/audit-log", tags=["Audit Log"])

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


class AuditEntryResponse(BaseModel):
    id: str
    actionCode: str
    entityType: str
    entityId: str
    actorUserId: str | None
    metadata: dict[str, Any]
    occurredAt: str


def _to_response(entry: AuditEntryDetails) -> AuditEntryResponse:
    return AuditEntryResponse(
        id=str(entry.id),
        actionCode=entry.action_code,
        entityType=entry.entity_type,
        entityId=str(entry.entity_id),
        actorUserId=str(entry.actor_user_id) if entry.actor_user_id else None,
        metadata=entry.metadata_json,
        occurredAt=entry.occurred_at.isoformat(),
    )


@router.get("", response_model=list[AuditEntryResponse], summary="Query audit entries")
async def query_audit_log(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: CurrentUser,
    entity_type: Annotated[str | None, Query(alias="entityType")] = None,
    entity_id: Annotated[uuid.UUID | None, Query(alias="entityId")] = None,
    action_code: Annotated[str | None, Query(alias="actionCode")] = None,
    date_from: Annotated[datetime | None, Query(alias="dateFrom")] = None,
    date_to: Annotated[datetime | None, Query(alias="dateTo")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[AuditEntryResponse]:
    entries = await AuditService(session).query_entries(
        actor_user_id=current_user.id,
        entity_type=entity_type,
        entity_id=entity_id,
        action_code=action_code,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
    )
    return [_to_response(e) for e in entries]


@router.get(
    "/{entry_id}",
    response_model=AuditEntryResponse,
    summary="Get a single audit entry",
)
async def get_audit_entry(
    entry_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    current_user: CurrentUser,
) -> AuditEntryResponse:
    entries = await AuditService(session).query_entries(actor_user_id=current_user.id, limit=200)
    for entry in entries:
        if entry.id == entry_id:
            return _to_response(entry)
    from src.domain.errors import NotFoundError

    raise NotFoundError()

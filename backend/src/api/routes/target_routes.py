"""Target endpoints (SRS Chapter 5, Section 4; schema Chapter 4, Section 4.4).

All routes require an authenticated principal (``CurrentUser``) and enforce
tenant isolation server-side: resources owned by another entity are reported
as 404 NOT_FOUND so nothing about other organizations' data leaks.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import CurrentUser  # noqa: TC001 - resolved by FastAPI at runtime
from src.config.constants import SCAN_STATUS_PENDING_ATTESTATION
from src.domain.errors import InvalidPaginationCursorError
from src.domain.targets.target_service import TargetDetails, TargetService
from src.infrastructure.database.connection import get_db_session

router = APIRouter(prefix="/targets", tags=["Targets"])

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


class CreateTargetRequest(BaseModel):
    """POST /targets request body (SRS Chapter 5, Section 4)."""

    hostname: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2000)
    owner_organization_id: uuid.UUID | None = Field(
        default=None,
        validation_alias="ownerOrganizationId",
    )


class UpdateTargetRequest(BaseModel):
    """PATCH /targets/{targetId} body — hostname/URL are immutable."""

    model_config = ConfigDict(extra="forbid")

    is_archived: bool = Field(validation_alias="isArchived")


class TargetResponse(BaseModel):
    """Target representation incl. derived attestation status.

    ``status`` is always PENDING_ATTESTATION until the authorization
    attestation feature lands (Chapter 5 Section 4/5): a target exists but is
    unscannable until a CONFIRMED attestation is presented.
    """

    id: uuid.UUID
    hostname: str
    normalized_url: str = Field(serialization_alias="url")
    owner_organization_id: uuid.UUID | None = Field(serialization_alias="ownerOrganizationId")
    owner_user_id: uuid.UUID | None = Field(serialization_alias="ownerUserId")
    is_archived: bool = Field(serialization_alias="isArchived")
    created_at: datetime = Field(serialization_alias="createdAt")
    status: str = SCAN_STATUS_PENDING_ATTESTATION


class PageInfo(BaseModel):
    """Cursor-pagination metadata (SRS Chapter 5, Section 16)."""

    next_cursor: str | None = Field(serialization_alias="nextCursor")
    has_next_page: bool = Field(serialization_alias="hasNextPage")


class TargetListResponse(BaseModel):
    """Paginated list envelope (SRS Chapter 5, Section 16)."""

    items: list[TargetResponse]
    page_info: PageInfo = Field(serialization_alias="pageInfo")


def _encode_cursor(created_at: datetime, target_id: uuid.UUID) -> str:
    raw = json.dumps({"c": created_at.isoformat(), "i": str(target_id)}).encode()
    return base64.urlsafe_b64encode(raw).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return (
            datetime.fromisoformat(str(raw["c"])),
            uuid.UUID(str(raw["i"])),
        )
    except Exception as exc:  # noqa: BLE001 - any decode failure is a 400
        raise InvalidPaginationCursorError() from exc


def _to_response(details: TargetDetails) -> TargetResponse:
    return TargetResponse(
        id=details.id,
        hostname=details.hostname,
        normalized_url=details.normalized_url,
        owner_organization_id=details.owner_organization_id,
        owner_user_id=details.owner_user_id,
        is_archived=details.is_archived,
        created_at=details.created_at,
    )


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new target",
)
async def create_target(
    payload: CreateTargetRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> TargetResponse:
    """Register a target for the requesting user or a member organization."""
    service = TargetService(session, current_user)
    details = await service.register_target(
        hostname=payload.hostname,
        url=payload.url,
        owner_organization_id=payload.owner_organization_id,
    )
    return _to_response(details)


@router.get(
    "",
    response_model=TargetListResponse,
    summary="List targets owned by the current user or a member organization",
)
async def list_targets(
    session: SessionDep,
    current_user: CurrentUser,
    organization_id: Annotated[uuid.UUID | None, Query(alias="organizationId")] = None,
    include_archived: Annotated[bool, Query(alias="includeArchived")] = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: Annotated[str | None, Query()] = None,
) -> TargetListResponse:
    cursor_created_at: datetime | None = None
    cursor_id: uuid.UUID | None = None
    if cursor is not None:
        cursor_created_at, cursor_id = _decode_cursor(cursor)

    service = TargetService(session, current_user)
    page = await service.list_targets(
        organization_id=organization_id,
        include_archived=include_archived,
        limit=limit,
        cursor_created_at=cursor_created_at,
        cursor_id=cursor_id,
    )
    next_cursor = (
        _encode_cursor(page.items[-1].created_at, page.items[-1].id)
        if page.has_next_page and page.items
        else None
    )
    return TargetListResponse(
        items=[_to_response(item) for item in page.items],
        page_info=PageInfo(next_cursor=next_cursor, has_next_page=page.has_next_page),
    )


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Get target detail",
)
async def get_target(
    target_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> TargetResponse:
    service = TargetService(session, current_user)
    return _to_response(await service.get_target(target_id))


@router.patch(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Update target metadata (hostname/URL immutable)",
)
async def update_target(
    target_id: uuid.UUID,
    payload: UpdateTargetRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> TargetResponse:
    service = TargetService(session, current_user)
    details = await service.set_archived(target_id, payload.is_archived)
    return _to_response(details)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archive (soft-delete) a target",
    description=(
        "Sets isArchived=true. Hard delete is never permitted once scan "
        "lifecycle data references the target (SRS Chapter 4, Section 13)."
    ),
)
async def delete_target(
    target_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> None:
    service = TargetService(session, current_user)
    await service.archive_target(target_id)

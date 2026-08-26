"""Organization & membership endpoints (SRS Chapter 5, Section 3).

All /organizations/{orgId}/... endpoints independently re-verify membership
server-side; mutating endpoints require ADMIN (Chapter 3, Section 18).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import CurrentUser  # noqa: TC001 - FastAPI runtime
from src.domain.audit.audit_service import AuditService
from src.domain.organizations.organization_service import (
    MembershipDetails,
    OrganizationService,
)
from src.infrastructure.database.connection import get_db_session

router = APIRouter(tags=["Organizations"])

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime = Field(serialization_alias="createdAt")


class AddMemberRequest(BaseModel):
    user_id: uuid.UUID = Field(serialization_alias="userId")
    role: str = Field(pattern="^(ADMIN|MEMBER)$")


class ChangeRoleRequest(BaseModel):
    role: str = Field(pattern="^(ADMIN|MEMBER)$")


class MembershipResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID = Field(serialization_alias="organizationId")
    user_id: uuid.UUID = Field(serialization_alias="userId")
    role: str
    created_at: datetime = Field(serialization_alias="createdAt")


def _service(session: AsyncSession, current_user: Any) -> OrganizationService:
    return OrganizationService(session, current_user)


def _to_org_response(details) -> OrganizationResponse:  # type: ignore[no-untyped-def]
    return OrganizationResponse(id=details.id, name=details.name, created_at=details.created_at)


def _to_membership_response(details: MembershipDetails) -> MembershipResponse:
    return MembershipResponse(
        id=details.id,
        organization_id=details.organization_id,
        user_id=details.user_id,
        role=details.role,
        created_at=details.created_at,
    )


@router.post(
    "/organizations",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization (creator becomes ADMIN)",
)
async def create_organization(
    payload: CreateOrganizationRequest, session: SessionDep, current_user: CurrentUser
) -> OrganizationResponse:
    details = await _service(session, current_user).create_organization(payload.name)
    org_response = _to_org_response(details)
    await AuditService(session).record(
        action_code="ORGANIZATION_CREATED",
        entity_type="organization",
        entity_id=details.id,
        metadata_json={"name": details.name},
        actor_user_id=current_user.id,
    )
    return org_response


@router.get(
    "/organizations/{org_id}",
    response_model=OrganizationResponse,
    summary="Get organization detail (member required)",
)
async def get_organization(
    org_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> OrganizationResponse:
    return _to_org_response(await _service(session, current_user).get_organization(org_id))


@router.get(
    "/organizations/{org_id}/members",
    response_model=list[MembershipResponse],
    summary="List members (member required)",
)
async def list_members(
    org_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> list[MembershipResponse]:
    rows = await _service(session, current_user).list_members(org_id)
    return [_to_membership_response(r) for r in rows]


@router.post(
    "/organizations/{org_id}/members",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a member by email (ADMIN required)",
)
async def add_member(
    org_id: uuid.UUID,
    payload: AddMemberRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> MembershipResponse:
    details = await _service(session, current_user).add_member(
        org_id, user_id=payload.user_id, role=payload.role
    )
    await AuditService(session).record(
        action_code="MEMBER_ADDED",
        entity_type="organization",
        entity_id=org_id,
        metadata_json={"memberUserId": str(details.user_id), "role": details.role},
        actor_user_id=current_user.id,
    )
    return _to_membership_response(details)


@router.patch(
    "/organizations/{org_id}/members/{user_id}",
    response_model=MembershipResponse,
    summary="Change a member's role (ADMIN required)",
)
async def change_member_role(
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    payload: ChangeRoleRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> MembershipResponse:
    details = await _service(session, current_user).change_role(org_id, user_id, role=payload.role)
    await AuditService(session).record(
        action_code="MEMBER_ROLE_CHANGED",
        entity_type="organization",
        entity_id=org_id,
        metadata_json={"memberUserId": str(user_id), "role": details.role},
        actor_user_id=current_user.id,
    )
    return _to_membership_response(details)


@router.delete(
    "/organizations/{org_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member (ADMIN required)",
)
async def remove_member(
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> None:
    await _service(session, current_user).remove_member(org_id, user_id)
    await AuditService(session).record(
        action_code="MEMBER_REMOVED",
        entity_type="organization",
        entity_id=org_id,
        metadata_json={"memberUserId": str(user_id)},
        actor_user_id=current_user.id,
    )

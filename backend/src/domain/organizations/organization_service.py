"""Organization & membership domain service (SRS Chapter 5 §3; Ch. 4 §4.2-4.3).

Server-enforced authorization per Chapter 3 §18: every endpoint
independently re-verifies membership; mutating endpoints require ADMIN.
The creator of a new organization is auto-assigned ADMIN.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.domain.errors import ForbiddenError, NotFoundError
from src.infrastructure.database.models.identity_models import (
    ROLE_ADMIN,
    Organization,
    OrganizationMembership,
)
from src.infrastructure.database.repositories.membership_repository import (
    MembershipRepository,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount


@dataclass(frozen=True)
class OrganizationDetails:
    id: uuid.UUID
    name: str
    created_at: datetime


@dataclass(frozen=True)
class MembershipDetails:
    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID
    role: str
    created_at: datetime


class OrganizationService:
    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._session = session
        self._principal = principal
        self._memberships = MembershipRepository(session)

    # ------------------------------------------------------------------ #
    # Queries (member required)                                          #
    # ------------------------------------------------------------------ #

    async def create_organization(self, name: str) -> OrganizationDetails:
        org = Organization(id=uuid.uuid4(), name=name[:255])
        self._session.add(org)
        membership = OrganizationMembership(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=self._principal.id,
            role=ROLE_ADMIN,
        )
        self._memberships.add_membership(membership)
        await self._memberships.flush()
        return _to_org_details(org)

    async def get_organization(self, org_id: uuid.UUID) -> OrganizationDetails:
        await self._require_member(org_id)
        org = await self._session.get(Organization, org_id)
        if org is None:  # pragma: no cover - membership implies existence
            raise NotFoundError()
        return _to_org_details(org)

    async def list_members(self, org_id: uuid.UUID) -> list[MembershipDetails]:
        await self._require_member(org_id)
        rows = await self._memberships.list_members(org_id)
        return [_to_membership_details(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Mutations (ADMIN required)                                         #
    # ------------------------------------------------------------------ #

    async def add_member(
        self, org_id: uuid.UUID, *, user_id: uuid.UUID, role: str
    ) -> MembershipDetails:
        if not await self._is_admin(org_id):
            raise ForbiddenError()
        existing = await self._memberships.get_membership(org_id, user_id)
        if existing is not None:
            return _to_membership_details(existing)
        membership = OrganizationMembership(
            id=uuid.uuid4(),
            organization_id=org_id,
            user_id=user_id,
            role=role,
        )
        self._memberships.add_membership(membership)
        await self._memberships.flush()
        return _to_membership_details(membership)

    async def change_role(
        self, org_id: uuid.UUID, member_user_id: uuid.UUID, *, role: str
    ) -> MembershipDetails:
        membership = await self._require_admin_and_get(org_id, member_user_id)
        if membership.role == ROLE_ADMIN and role != ROLE_ADMIN:
            await self._require_remaining_admin(org_id, member_user_id)
        membership.role = role
        await self._session.flush()
        return _to_membership_details(membership)

    async def remove_member(self, org_id: uuid.UUID, member_user_id: uuid.UUID) -> None:
        membership = await self._require_admin_and_get(org_id, member_user_id)
        if membership.role == ROLE_ADMIN:
            await self._require_remaining_admin(org_id, member_user_id)
        await self._memberships.delete_membership(membership)
        await self._memberships.flush()

    # ------------------------------------------------------------------ #

    async def _require_member(self, org_id: uuid.UUID) -> None:
        if not await self._memberships.is_member(self._principal.id, org_id):
            raise NotFoundError()  # indistinguishable from missing

    async def _is_admin(self, org_id: uuid.UUID) -> bool:
        return await self._memberships.is_admin(self._principal.id, org_id)

    async def _require_remaining_admin(self, org_id: uuid.UUID, member_user_id: uuid.UUID) -> None:
        """Refuse to demote/remove the last ADMIN (unrecoverable tenant)."""
        members = await self._memberships.list_members(org_id)
        admins = [m for m in members if m.role == ROLE_ADMIN]
        if len(admins) <= 1 and any(m.user_id == member_user_id for m in admins):
            raise ForbiddenError()

    async def _require_admin_and_get(
        self, org_id: uuid.UUID, member_user_id: uuid.UUID
    ) -> OrganizationMembership:
        if not await self._is_admin(org_id):
            raise ForbiddenError()
        membership = await self._memberships.get_membership(org_id, member_user_id)
        if membership is None:
            raise NotFoundError()
        return membership


def _to_org_details(org: Organization) -> OrganizationDetails:
    return OrganizationDetails(id=org.id, name=org.name, created_at=org.created_at)


def _to_membership_details(row: OrganizationMembership) -> MembershipDetails:
    return MembershipDetails(
        id=row.id,
        organization_id=row.organization_id,
        user_id=row.user_id,
        role=row.role,
        created_at=row.created_at,
    )

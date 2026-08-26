"""Organization membership repository: access-control lookups."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from src.infrastructure.database.models import OrganizationMembership

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


class MembershipRepository:
    """Data-access boundary for organization membership checks."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def is_member(self, user_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """True when the user holds any role in the organization."""
        stmt = select(OrganizationMembership.id).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
        row = (await self._session.execute(stmt)).first()
        return row is not None

    def add_membership(self, membership: OrganizationMembership) -> None:
        """Stage a membership row for the next flush (repository pattern)."""
        self._session.add(membership)

    async def flush(self) -> None:
        await self._session.flush()

    async def delete_membership(self, membership: OrganizationMembership) -> None:
        await self._session.delete(membership)

    async def get_membership(
        self, organization_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMembership | None:
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
        return (await self._session.execute(stmt)).scalars().first()

    async def list_members(self, organization_id: uuid.UUID) -> list[OrganizationMembership]:
        stmt = (
            select(OrganizationMembership)
            .where(OrganizationMembership.organization_id == organization_id)
            .order_by(OrganizationMembership.created_at.asc())
        )
        rows = await self._session.execute(stmt)
        return list(rows.scalars().all())

    async def is_admin(self, user_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """True when the user holds the ADMIN role in the organization."""
        membership = await self.get_membership(organization_id, user_id)
        return membership is not None and membership.role == "ADMIN"

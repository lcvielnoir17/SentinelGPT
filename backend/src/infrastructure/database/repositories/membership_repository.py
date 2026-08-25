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
        stmt = (
            select(OrganizationMembership.id)
            .where(
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.organization_id == organization_id,
            )
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

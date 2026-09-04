"""Target domain service: registration, retrieval, listing, archiving.

Implements the SRS Chapter 5 Section 4 Target contract against the Chapter 4
Section 4.4 schema. Access rules (Chapter 3 Section 18, server-side only):

* A target is visible to its owning user or to members of the owning
  organization — everyone else receives 404 NOT_FOUND (no existence leak).
* Creating under an organization requires membership of that organization.
* hostname/URL are immutable; a URL change is a new target (Chapter 5 §4).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.domain.errors import DuplicateTargetError, ForbiddenError, NotFoundError
from src.domain.targets.target_normalization import normalize_target
from src.infrastructure.database.models import Target
from src.infrastructure.database.repositories.membership_repository import (
    MembershipRepository,
)
from src.infrastructure.database.repositories.target_repository import TargetRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount


@dataclass(frozen=True)
class TargetDetails:
    """Framework-agnostic target entity returned by domain services."""

    id: uuid.UUID
    hostname: str
    normalized_url: str
    owner_organization_id: uuid.UUID | None
    owner_user_id: uuid.UUID | None
    is_archived: bool
    created_at: datetime


@dataclass(frozen=True)
class TargetPage:
    """Keyset-paginated target list result."""

    items: list[TargetDetails]
    has_next_page: bool


class TargetService:
    """Business rules for the ``target`` aggregate."""

    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._principal = principal
        self._session = session
        self._repository = TargetRepository(session)
        self._memberships = MembershipRepository(session)

    async def register_target(
        self,
        hostname: str,
        url: str,
        owner_organization_id: uuid.UUID | None,
    ) -> TargetDetails:
        """Create a target owned by an organization (member required) or the user."""
        normalized = normalize_target(hostname, url)

        if owner_organization_id is not None:
            if not await self._memberships.is_member(self._principal.id, owner_organization_id):
                raise ForbiddenError()
            owner_organization: uuid.UUID | None = owner_organization_id
            owner_user: uuid.UUID | None = None
        else:
            owner_organization = None
            owner_user = self._principal.id

        existing = await self._repository.find_by_owner_and_url(
            owner_organization_id=owner_organization,
            owner_user_id=owner_user,
            normalized_url=normalized.normalized_url,
        )
        if existing is not None:
            raise DuplicateTargetError()

        now = datetime.now(UTC)
        target = Target(
            id=uuid.uuid4(),
            owner_organization_id=owner_organization,
            owner_user_id=owner_user,
            hostname=normalized.hostname,
            normalized_url=normalized.normalized_url,
            is_archived=False,
            created_at=now,
        )
        from sqlalchemy.exc import IntegrityError

        try:
            self._repository.add(target)
            await self._repository.flush()
        except IntegrityError as exc:
            # A concurrent identical insert won the race after our
            # existence check. Roll back and re-check to distinguish a
            # true duplicate (409) from any other constraint violation.
            await self._session.rollback()
            raced = await self._repository.find_by_owner_and_url(
                owner_organization_id=owner_organization,
                owner_user_id=owner_user,
                normalized_url=normalized.normalized_url,
            )
            if raced is not None:
                raise DuplicateTargetError() from exc
            raise
        return _to_details(target)

    async def get_target(self, target_id: uuid.UUID) -> TargetDetails:
        """Fetch one target if it exists and is visible to the requester."""
        target = await self._get_visible_target(target_id)
        return _to_details(target)

    async def list_targets(
        self,
        *,
        organization_id: uuid.UUID | None,
        include_archived: bool,
        limit: int,
        cursor_created_at: datetime | None,
        cursor_id: uuid.UUID | None,
    ) -> TargetPage:
        """List targets for the requester's personal scope or a member org."""
        if organization_id is not None and not await self._memberships.is_member(
            self._principal.id, organization_id
        ):
            raise ForbiddenError()

        rows = await self._repository.list_for_owner(
            owner_organization_id=organization_id,
            owner_user_id=None if organization_id is not None else self._principal.id,
            include_archived=include_archived,
            limit=limit + 1,
            cursor_created_at=cursor_created_at,
            cursor_id=cursor_id,
        )
        has_next = len(rows) > limit
        return TargetPage(
            items=[_to_details(row) for row in rows[:limit]],
            has_next_page=has_next,
        )

    async def set_archived(self, target_id: uuid.UUID, is_archived: bool) -> TargetDetails:
        """Archive/unarchive a target (the only mutable metadata per SRS)."""
        target = await self._get_visible_target(target_id)
        target.is_archived = is_archived
        await self._repository.flush()
        return _to_details(target)

    async def archive_target(self, target_id: uuid.UUID) -> None:
        """Soft-delete a target (204); hard delete is never exposed."""
        target = await self._get_visible_target(target_id)
        target.is_archived = True
        await self._repository.flush()

    async def _get_visible_target(self, target_id: uuid.UUID) -> Target:
        target = await self._repository.get_by_id(target_id)
        if target is None:
            raise NotFoundError()
        if target.owner_user_id == self._principal.id:
            return target
        if target.owner_organization_id is not None and await self._memberships.is_member(
            self._principal.id, target.owner_organization_id
        ):
            return target
        # Cross-tenant targets are indistinguishable from missing ones.
        raise NotFoundError()


def _to_details(target: Target) -> TargetDetails:
    return TargetDetails(
        id=target.id,
        hostname=target.hostname,
        normalized_url=target.normalized_url,
        owner_organization_id=target.owner_organization_id,
        owner_user_id=target.owner_user_id,
        is_archived=target.is_archived,
        created_at=target.created_at,
    )

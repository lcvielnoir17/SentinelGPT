"""Target repository: persistence access for target use cases.

Query construction lives here per the repository pattern (SRS Chapter 3,
Section 11) — services never build SQLAlchemy queries inline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import and_, or_, select

from src.infrastructure.database.models import Target

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


class TargetRepository:
    """Data-access boundary for the ``target`` aggregate."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_by_owner_and_url(
        self,
        *,
        owner_organization_id: uuid.UUID | None,
        owner_user_id: uuid.UUID | None,
        normalized_url: str,
    ) -> Target | None:
        """Fetch a target for a specific owning entity and canonical URL."""
        stmt = select(Target).where(
            Target.normalized_url == normalized_url,
        )
        if owner_organization_id is None:
            stmt = stmt.where(Target.owner_organization_id.is_(None))
        else:
            stmt = stmt.where(Target.owner_organization_id == owner_organization_id)
        if owner_user_id is None:
            stmt = stmt.where(Target.owner_user_id.is_(None))
        else:
            stmt = stmt.where(Target.owner_user_id == owner_user_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id(self, target_id: uuid.UUID) -> Target | None:
        """Fetch a single target by primary key."""
        stmt = select(Target).where(Target.id == target_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_owner(
        self,
        *,
        owner_organization_id: uuid.UUID | None,
        owner_user_id: uuid.UUID | None,
        include_archived: bool,
        limit: int,
        cursor_created_at: datetime | None,
        cursor_id: uuid.UUID | None,
    ) -> list[Target]:
        """Keyset-paginated listing ordered by (created_at DESC, id DESC)."""
        stmt = select(Target)
        if owner_organization_id is None:
            stmt = stmt.where(Target.owner_organization_id.is_(None))
        else:
            stmt = stmt.where(Target.owner_organization_id == owner_organization_id)
        if owner_user_id is None:
            stmt = stmt.where(Target.owner_user_id.is_(None))
        else:
            stmt = stmt.where(Target.owner_user_id == owner_user_id)
        if not include_archived:
            stmt = stmt.where(Target.is_archived.is_(False))
        if cursor_created_at is not None and cursor_id is not None:
            # Explicit keyset predicate: (created_at, id) < (cursor, tiebreak).
            stmt = stmt.where(
                or_(
                    Target.created_at < cursor_created_at,
                    and_(
                        Target.created_at == cursor_created_at,
                        Target.id < cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(Target.created_at.desc(), Target.id.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    def add(self, target: Target) -> None:
        """Stage a new target row; committed by the request-scoped session."""
        self._session.add(target)

    async def flush(self) -> None:
        """Flush pending writes so server defaults (ids/timestamps) populate.

        The commit itself stays with the request-scoped ``get_db_session``
        dependency (commit-on-success / rollback-on-exception), per SRS
        Chapter 6, Section 9.
        """
        await self._session.flush()

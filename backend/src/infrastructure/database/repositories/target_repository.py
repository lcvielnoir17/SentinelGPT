"""Target repository: persistence access for target use cases.

Query construction lives here per the repository pattern (SRS Chapter 3,
Section 11) — services never build SQLAlchemy queries inline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import and_, or_, select

from src.infrastructure.database.models import Target, TargetTechnology

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
        owner_user_id: uuid.UUID,
        normalized_url: str,
    ) -> Target | None:
        """Fetch a target for a specific owning user and canonical URL."""
        stmt = select(Target).where(
            Target.normalized_url == normalized_url,
            Target.owner_user_id == owner_user_id,
        )
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
        owner_user_id: uuid.UUID,
        include_archived: bool,
        limit: int,
        cursor_created_at: datetime | None,
        cursor_id: uuid.UUID | None,
    ) -> list[Target]:
        """Keyset-paginated listing ordered by (created_at DESC, id DESC)."""
        stmt = select(Target).where(Target.owner_user_id == owner_user_id)
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

    async def list_technologies(self, target_id: uuid.UUID) -> list[dict[str, object]]:
        """Detected technology inventory for one target, slug-ordered."""
        rows = await self._session.execute(
            select(TargetTechnology)
            .where(TargetTechnology.target_id == target_id)
            .order_by(TargetTechnology.slug.asc())
        )
        return [self._technology_dto(row) for row in rows.scalars().all()]

    async def upsert_technology(
        self,
        *,
        target_id: uuid.UUID,
        slug: str,
        display: str,
        family: str,
        version: str | None,
        confidence: str,
        source: str,
        observed_in_scan_id: uuid.UUID | None,
    ) -> dict[str, object]:
        """Insert or refresh one technology row (latest observation wins,
        first observation preserved). Sources merge deterministically."""
        from datetime import UTC, datetime

        existing = await self._session.execute(
            select(TargetTechnology).where(
                TargetTechnology.target_id == target_id,
                TargetTechnology.slug == slug,
            )
        )
        row = existing.scalars().first()
        now = datetime.now(UTC)
        if row is not None:
            row.display = display
            row.family = family
            row.version = version
            row.confidence = _max_confidence(str(row.confidence), confidence)
            merged = sorted(set(str(row.sources or "").split(",")) | {source})
            row.sources = ",".join(s for s in merged if s)[:500]
            row.last_observed_at = now
            row.observed_in_scan_id = observed_in_scan_id
            await self._session.flush()
            return self._technology_dto(row)
        row = TargetTechnology(
            target_id=target_id,
            slug=slug,
            display=display,
            family=family,
            version=version,
            confidence=confidence,
            sources=source[:500],
            first_observed_at=now,
            last_observed_at=now,
            observed_in_scan_id=observed_in_scan_id,
        )
        self._session.add(row)
        await self._session.flush()
        return self._technology_dto(row)

    @staticmethod
    def _technology_dto(row: TargetTechnology) -> dict[str, object]:
        return {
            "id": str(row.id),
            "target_id": str(row.target_id),
            "slug": row.slug,
            "display": row.display,
            "family": row.family,
            "version": row.version,
            "confidence": row.confidence,
            "sources": str(row.sources or ""),
            "first_observed_at": row.first_observed_at.isoformat()
            if row.first_observed_at
            else None,
            "last_observed_at": row.last_observed_at.isoformat() if row.last_observed_at else None,
            "observed_in_scan_id": str(row.observed_in_scan_id)
            if row.observed_in_scan_id is not None
            else None,
        }

    async def flush(self) -> None:
        """Flush pending writes so server defaults (ids/timestamps) populate.

        The commit itself stays with the request-scoped ``get_db_session``
        dependency (commit-on-success / rollback-on-exception), per SRS
        Chapter 6, Section 9.
        """
        await self._session.flush()


_CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _max_confidence(current: str, incoming: str) -> str:
    """Higher of two confidence levels (unknown values keep the current)."""
    if _CONFIDENCE_RANK.get(incoming, -1) > _CONFIDENCE_RANK.get(current, -1):
        return incoming
    return current

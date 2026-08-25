"""Refresh-session repository: persistence access for session rotation.

All status transitions that security depends on are expressed as atomic
conditional UPDATE statements so concurrent requests cannot rotate one
credential twice or resurrect a revoked family (SRS Chapter 5 Section 2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import select, update

from src.infrastructure.database.models.refresh_session_models import (
    SESSION_ACTIVE,
    SESSION_REVOKED,
    SESSION_ROTATED,
    RefreshSession,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import AsyncSession


class RefreshSessionRepository:
    """Data-access boundary for the ``refresh_session`` aggregate."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_token_hash(self, token_hash: str) -> RefreshSession | None:
        stmt = select(RefreshSession).where(RefreshSession.token_hash == token_hash)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def try_mark_rotated(self, session_id: uuid.UUID) -> bool:
        """Atomically ACTIVE -> ROTATED. False means lost race / not active."""
        stmt = (
            update(RefreshSession)
            .where(RefreshSession.id == session_id, RefreshSession.status == SESSION_ACTIVE)
            .values(status=SESSION_ROTATED)
        )
        result = await self._session.execute(stmt)
        return cast("CursorResult[Any]", result).rowcount == 1

    async def revoke_family(self, family_id: uuid.UUID) -> None:
        stmt = (
            update(RefreshSession)
            .where(RefreshSession.family_id == family_id)
            .values(status=SESSION_REVOKED)
        )
        await self._session.execute(stmt)

    async def revoke(self, session_id: uuid.UUID) -> None:
        stmt = (
            update(RefreshSession)
            .where(RefreshSession.id == session_id)
            .values(status=SESSION_REVOKED)
        )
        await self._session.execute(stmt)

    def add(self, refresh_session: RefreshSession) -> None:
        """Stage a new child credential; committed by the request-scoped session."""
        self._session.add(refresh_session)

    async def flush(self) -> None:
        await self._session.flush()


__all__ = [
    "RefreshSession",
    "RefreshSessionRepository",
    "SESSION_ACTIVE",
    "SESSION_REVOKED",
    "SESSION_ROTATED",
]

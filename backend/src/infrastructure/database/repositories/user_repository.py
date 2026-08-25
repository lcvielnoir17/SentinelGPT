"""User repository: persistence access for identity use cases.

Query construction lives here per the repository pattern (SRS Chapter 3,
Section 11) — services never build SQLAlchemy queries inline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from src.infrastructure.database.models import User

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


class UserRepository:
    """Data-access boundary for the ``user`` aggregate."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email(self, email: str) -> User | None:
        """Fetch a user by (unique, case-preserved) email address."""
        stmt = select(User).where(User.email == email)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Fetch a user by primary key (used by the auth dependency)."""
        stmt = select(User).where(User.id == user_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    def add(self, user: User) -> None:
        """Stage a new user row; committed by the request-scoped session."""
        self._session.add(user)

    async def flush(self) -> None:
        """Flush pending writes so server defaults (ids/timestamps) populate.

        The commit itself stays with the request-scoped ``get_db_session``
        dependency (commit-on-success / rollback-on-exception), per SRS
        Chapter 6, Section 9.
        """
        await self._session.flush()

"""CI repository: credentials and idempotent trigger ledger."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from src.infrastructure.database.models import CiCredential, CiScanRequest

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


class CiRepository:
    """Data-access boundary for the ``ci_credential`` aggregate."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add_credential(self, credential: CiCredential) -> None:
        """Stage a new credential row; committed by the caller."""
        self._session.add(credential)

    async def flush(self) -> None:
        await self._session.flush()

    async def get_credential(self, credential_id: uuid.UUID) -> CiCredential | None:
        """Fetch one credential by id (owner checks happen in the service)."""
        return await self._session.get(CiCredential, credential_id)

    async def list_for_owner(self, owner_id: uuid.UUID) -> list[CiCredential]:
        """All credentials owned by the user, oldest first (stable order)."""
        result = await self._session.execute(
            select(CiCredential)
            .where(CiCredential.owner_user_id == owner_id)
            .order_by(CiCredential.created_at.asc())
        )
        return list(result.scalars().all())

    def add_request(self, request: CiScanRequest) -> None:
        """Stage a trigger-ledger row; committed by the caller."""
        self._session.add(request)

    async def get_request_by_key(
        self, credential_id: uuid.UUID, idempotency_key: str
    ) -> CiScanRequest | None:
        """The live claim for one (credential, key) pair, if any."""
        result = await self._session.execute(
            select(CiScanRequest).where(
                CiScanRequest.credential_id == credential_id,
                CiScanRequest.idempotency_key == idempotency_key,
            )
        )
        return result.scalars().first()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()


__all__ = ["CiRepository"]

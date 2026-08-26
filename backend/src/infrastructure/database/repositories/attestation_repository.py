"""Attestation repository: authorization-to-scan records (Ch. 4 §8)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select

from src.infrastructure.database.models import AuthorizationAttestation

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

CONFIRMED = "CONFIRMED"
REVOKED = "REVOKED"


class AttestationRepository:
    """Data-access boundary for ``authorization_attestation``."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, attestation: AuthorizationAttestation) -> None:
        self._session.add(attestation)

    async def flush(self) -> None:
        await self._session.flush()

    async def get_by_id(self, attestation_id: uuid.UUID) -> AuthorizationAttestation | None:
        return await self._session.get(AuthorizationAttestation, attestation_id)

    async def list_for_target(self, target_id: uuid.UUID) -> list[AuthorizationAttestation]:
        stmt = (
            select(AuthorizationAttestation)
            .where(AuthorizationAttestation.target_id == target_id)
            .order_by(AuthorizationAttestation.created_at.desc())
        )
        rows = await self._session.execute(stmt)
        return list(rows.scalars().all())

    async def has_active_confirmed(self, target_id: uuid.UUID) -> bool:
        """True when ≥1 CONFIRMED non-expired attestation exists (Ch. 5 §5 gate)."""
        now = datetime.now(UTC)
        stmt = select(AuthorizationAttestation.id).where(
            AuthorizationAttestation.target_id == target_id,
            AuthorizationAttestation.status == CONFIRMED,
            (AuthorizationAttestation.expires_at.is_(None))
            | (AuthorizationAttestation.expires_at > now),
        )
        row = (await self._session.execute(stmt)).first()
        return row is not None

    async def method_code_map(self) -> dict[int, str]:
        """Stable {id: code} mapping for attestation methods."""
        from src.infrastructure.database.models import AttestationMethod

        rows = await self._session.execute(select(AttestationMethod.id, AttestationMethod.code))
        mapping: dict[int, str] = {}
        for id_, code in rows:
            mapping[id_] = code
        return mapping

    async def latest_active_confirmed(
        self, target_id: uuid.UUID
    ) -> AuthorizationAttestation | None:
        """The most recent CONFIRMED non-expired attestation for a target."""
        now = datetime.now(UTC)
        stmt = (
            select(AuthorizationAttestation)
            .where(
                AuthorizationAttestation.target_id == target_id,
                AuthorizationAttestation.status == CONFIRMED,
                (AuthorizationAttestation.expires_at.is_(None))
                | (AuthorizationAttestation.expires_at > now),
            )
            .order_by(AuthorizationAttestation.created_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalars().first()

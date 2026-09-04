"""Authorization-attestation domain service (SRS Ch. 4 §8; Ch. 5 §5).

Registration alone never authorizes scanning. A target becomes scannable
only while it holds at least one CONFIRMED, unexpired attestation
(``SELF_ATTESTATION`` auto-confirms per Phase 7 policy). Attestations are
versioned history: revocation never deletes rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.domain.audit.audit_service import (
    ACTION_ATTESTATION_CONFIRMED,
    ACTION_ATTESTATION_REVOKED,
)
from src.domain.errors import InvalidAttestationError, NotFoundError
from src.infrastructure.database.models import AuthorizationAttestation
from src.infrastructure.database.repositories.attestation_repository import (
    CONFIRMED,
    REVOKED,
    AttestationRepository,
)
from src.infrastructure.database.repositories.membership_repository import (
    MembershipRepository,
)
from src.infrastructure.database.repositories.target_repository import TargetRepository

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount


@dataclass(frozen=True)
class AttestationDetails:
    """Framework-agnostic attestation entity."""

    id: uuid.UUID
    target_id: uuid.UUID
    method_code: str
    status: str
    expires_at: datetime | None
    evidence_file_ref: str | None
    created_by_user_id: uuid.UUID | None
    revoked_at: datetime | None
    revoked_reason: str | None
    created_at: datetime

    @property
    def is_active(self) -> bool:
        if self.status != CONFIRMED:
            return False
        if self.expires_at is None:
            return True
        return self.expires_at > datetime.now(UTC)


class AttestationService:
    """Business rules for the ``authorization_attestation`` aggregate."""

    SELF_ATTESTATION_CODE = "SELF_ATTESTATION"

    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._principal = principal
        self._session = session
        self._attestations = AttestationRepository(session)
        self._targets = TargetRepository(session)
        self._memberships = MembershipRepository(session)
        from src.domain.audit.audit_service import AuditService

        self._audit = AuditService(session)

    async def create_self_attestation(
        self,
        target_id: uuid.UUID,
        *,
        expires_at: datetime | None = None,
        evidence_file_ref: str | None = None,
    ) -> AttestationDetails:
        """Submit + auto-confirm a SELF_ATTESTATION for a visible target."""
        target = await self._require_visible_target(target_id)
        if getattr(target, "is_archived", False):
            # Archived targets cannot be scanned, so authorizing them would
            # mint a CONFIRMED attestation that no scan gate can ever use.
            raise NotFoundError()
        if expires_at is not None:
            if expires_at.tzinfo is None:
                raise InvalidAttestationError()
            if expires_at <= datetime.now(UTC):
                raise InvalidAttestationError()

        attestation = AuthorizationAttestation(
            target_id=target_id,
            method_id=await self._method_id(self.SELF_ATTESTATION_CODE),
            status=CONFIRMED,
            evidence_file_ref=evidence_file_ref,
            expires_at=expires_at,
            created_by_user_id=self._principal.id,
        )
        self._attestations.add(attestation)
        await self._attestations.flush()
        await self._audit.record(
            action_code=ACTION_ATTESTATION_CONFIRMED,
            entity_type="authorization_attestation",
            entity_id=attestation.id,
            metadata_json={
                "method": self.SELF_ATTESTATION_CODE,
                "targetId": str(target_id),
                "targetOwnerUserId": str(getattr(target, "owner_user_id", "") or ""),
                "targetOwnerOrganizationId": str(
                    getattr(target, "owner_organization_id", "") or ""
                ),
                "ownerUserId": str(self._principal.id),
                "expiresAt": expires_at.isoformat() if expires_at else None,
            },
            actor_user_id=self._principal.id,
        )
        return _to_details(attestation, self.SELF_ATTESTATION_CODE)

    async def list_for_target(self, target_id: uuid.UUID) -> list[AttestationDetails]:
        await self._require_visible_target(target_id)
        rows = await self._attestations.list_for_target(target_id)
        codes = await self._attestations.method_code_map()
        return [_to_details(r, codes.get(r.method_id, self.SELF_ATTESTATION_CODE)) for r in rows]

    async def revoke(self, attestation_id: uuid.UUID, *, reason: str) -> AttestationDetails:
        attestation = await self._attestations.get_by_id(attestation_id)
        if attestation is None:
            raise NotFoundError()
        await self._require_visible_target(attestation.target_id)

        codes = await self._attestations.method_code_map()
        if attestation.status == REVOKED:
            # Idempotent re-revoke: return current state without rewriting
            # history metadata or appending a duplicate audit row.
            return _to_details(
                attestation, codes.get(attestation.method_id, self.SELF_ATTESTATION_CODE)
            )
        attestation.status = REVOKED
        attestation.revoked_at = datetime.now(UTC)
        attestation.revoked_reason = reason[:1000]
        await self._attestations.flush()
        await self._audit.record(
            action_code=ACTION_ATTESTATION_REVOKED,
            entity_type="authorization_attestation",
            entity_id=attestation.id,
            metadata_json={"reason": reason[:1000]},
            actor_user_id=self._principal.id,
        )
        return _to_details(
            attestation, codes.get(attestation.method_id, self.SELF_ATTESTATION_CODE)
        )

    async def latest_active_confirmed(self, target_id: uuid.UUID) -> AttestationDetails | None:
        attestation = await self._attestations.latest_active_confirmed(target_id)
        if attestation is None:
            return None
        codes = await self._attestations.method_code_map()
        return _to_details(
            attestation, codes.get(attestation.method_id, self.SELF_ATTESTATION_CODE)
        )

    # ------------------------------------------------------------------ #

    async def _require_visible_target(self, target_id: uuid.UUID) -> object:
        target = await self._targets.get_by_id(target_id)
        if target is None:
            raise NotFoundError()
        if target.owner_user_id == self._principal.id:
            return target
        if target.owner_organization_id is not None and (
            await self._memberships.is_member(self._principal.id, target.owner_organization_id)
        ):
            return target
        raise NotFoundError()

    async def _method_id(self, code: str) -> int:
        from sqlalchemy import select

        from src.infrastructure.database.models import AttestationMethod

        row = (
            await self._session.execute(
                select(AttestationMethod.id).where(AttestationMethod.code == code)
            )
        ).first()
        if row is None:
            raise LookupError(f"attestation_method {code!r} is not seeded")
        return int(row[0])


def _to_details(attestation: AuthorizationAttestation, method_code: str) -> AttestationDetails:
    return AttestationDetails(
        id=attestation.id,
        target_id=attestation.target_id,
        method_code=method_code,
        status=attestation.status,
        expires_at=attestation.expires_at,
        evidence_file_ref=attestation.evidence_file_ref,
        created_by_user_id=attestation.created_by_user_id,
        revoked_at=attestation.revoked_at,
        revoked_reason=attestation.revoked_reason,
        created_at=attestation.created_at,
    )

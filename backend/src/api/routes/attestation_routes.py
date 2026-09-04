"""Authorization-attestation endpoints (SRS Chapter 5, Section 5).

A target is scannable only while it holds a CONFIRMED, unexpired
attestation. SELF_ATTESTATION auto-confirms in Phase 7; revocation is
immediate and historical rows are never deleted.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.scans.attestation_service import AttestationService

router = APIRouter(tags=["Authorization Attestations"])


class CreateAttestationRequest(BaseModel):
    method: str = Field(default="SELF_ATTESTATION", pattern="^SELF_ATTESTATION$")
    expires_at: datetime | None = Field(default=None, validation_alias="expiresAt")
    evidence_file_ref: str | None = Field(
        default=None,
        max_length=500,
        validation_alias="evidenceFileRef",
    )


class AttestationResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID = Field(serialization_alias="targetId")
    method: str
    status: str
    expires_at: datetime | None = Field(serialization_alias="expiresAt")
    evidence_file_ref: str | None = Field(serialization_alias="evidenceFileRef")
    revoked_at: datetime | None = Field(serialization_alias="revokedAt")
    revoked_reason: str | None = Field(serialization_alias="revokedReason")
    created_at: datetime = Field(serialization_alias="createdAt")


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


def _to_response(details: object) -> AttestationResponse:
    return AttestationResponse(
        id=details.id,  # type: ignore[attr-defined]
        target_id=details.target_id,  # type: ignore[attr-defined]
        method=details.method_code,  # type: ignore[attr-defined]
        status=details.status,  # type: ignore[attr-defined]
        expires_at=details.expires_at,  # type: ignore[attr-defined]
        evidence_file_ref=details.evidence_file_ref,  # type: ignore[attr-defined]
        revoked_at=details.revoked_at,  # type: ignore[attr-defined]
        revoked_reason=details.revoked_reason,  # type: ignore[attr-defined]
        created_at=details.created_at,  # type: ignore[attr-defined]
    )


@router.post(
    "/targets/{target_id}/attestations",
    response_model=AttestationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Authorize scanning of a target (self-attestation)",
)
async def create_attestation(
    target_id: uuid.UUID,
    payload: CreateAttestationRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> AttestationResponse:
    service = AttestationService(session, current_user)
    details = await service.create_self_attestation(
        target_id,
        expires_at=payload.expires_at,
        evidence_file_ref=payload.evidence_file_ref,
    )
    return _to_response(details)


@router.get(
    "/targets/{target_id}/attestations",
    response_model=list[AttestationResponse],
    summary="List attestation history for a target",
)
async def list_attestations(
    target_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> list[AttestationResponse]:
    rows = await AttestationService(session, current_user).list_for_target(target_id)
    return [_to_response(r) for r in rows]


@router.post(
    "/attestations/{attestation_id}/revoke",
    response_model=AttestationResponse,
    summary="Revoke an active attestation",
)
async def revoke_attestation(
    attestation_id: uuid.UUID,
    payload: RevokeRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> AttestationResponse:
    details = await AttestationService(session, current_user).revoke(
        attestation_id, reason=payload.reason
    )
    return _to_response(details)

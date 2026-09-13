"""CI/CD security API (generic automation entry point, M10).

Two authentication planes, never mixed:

* browser session (``CurrentUser``) — credential lifecycle only
  (create/list/rotate/revoke). No scan triggering here.
* bearer credential (``Authorization: Bearer sgptci_…``) — scan
  trigger + result only, strictly bound to the credential's target.
  No credential administration here.

Every trigger flows through ``ScanService.create_scan`` — ownership,
attestation, rate/queue limits, execution gate — so the existing
scan pipeline stays authoritative.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.ci.service import CiCredentialContext, CiService

router = APIRouter(prefix="/ci", tags=["CI"])


class CreateCredentialRequest(BaseModel):
    """POST /ci/credentials body."""

    name: str = Field(min_length=1, max_length=100)
    target_id: uuid.UUID = Field(validation_alias="targetId")
    expires_at: str | None = Field(default=None, validation_alias="expiresAt")


class CredentialMetadataResponse(BaseModel):
    """Credential metadata (secret material never included)."""

    id: uuid.UUID
    name: str
    target_id: uuid.UUID = Field(serialization_alias="targetId")
    scope: str
    key_prefix: str = Field(serialization_alias="keyPrefix")
    created_at: str = Field(serialization_alias="createdAt")
    last_used_at: str | None = Field(default=None, serialization_alias="lastUsedAt")
    expires_at: str | None = Field(default=None, serialization_alias="expiresAt")
    revoked_at: str | None = Field(default=None, serialization_alias="revokedAt")


class CreatedCredentialResponse(CredentialMetadataResponse):
    """Create/rotate response: metadata plus the secret, shown exactly once."""

    secret: str = Field(description="Raw bearer token; shown once, never again")


class TriggerScanRequest(BaseModel):
    """POST /ci/scans body (all fields optional)."""

    scan_profile: str | None = Field(default=None, validation_alias="scanProfile")
    idempotency_key: str | None = Field(default=None, validation_alias="idempotencyKey")
    policy: dict[str, Any] | None = None


def _to_metadata(row: dict[str, Any]) -> CredentialMetadataResponse:
    return CredentialMetadataResponse(
        id=row["id"],
        name=str(row["name"]),
        target_id=row["target_id"],
        scope=str(row["scope"]),
        key_prefix=str(row["key_prefix"]),
        created_at=_iso(row["created_at"]),
        last_used_at=_iso_or_none(row["last_used_at"]),
        expires_at=_iso_or_none(row["expires_at"]),
        revoked_at=_iso_or_none(row["revoked_at"]),
    )


def _iso(value: object) -> str:
    from datetime import datetime

    assert isinstance(value, datetime)
    return value.isoformat()


def _iso_or_none(value: object) -> str | None:
    return _iso(value) if value is not None else None


async def _ci_context(request: Request, session: SessionDep) -> CiCredentialContext:
    """Bearer authentication for the automation plane (401 on any failure)."""
    service = CiService(session, None)
    return await service.authenticate(request.headers.get("authorization"))


# --------------------------------------------------------------------- #
# Credential lifecycle (browser session)                                 #
# --------------------------------------------------------------------- #


@router.post(
    "/credentials",
    response_model=CreatedCredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a target-bound CI credential",
)
async def create_credential(
    payload: CreateCredentialRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> CreatedCredentialResponse:
    """Create a credential; the bearer token appears here exactly once."""
    created = await CiService(session, current_user).create_credential(
        name=payload.name,
        target_id=payload.target_id,
        expires_at=payload.expires_at,
    )
    response = _to_metadata(
        {
            "id": created.id,
            "name": created.name,
            "target_id": created.target_id,
            "scope": "scan",
            "key_prefix": created.key_prefix,
            "created_at": created.created_at,
            "last_used_at": None,
            "expires_at": created.expires_at,
            "revoked_at": None,
        }
    )
    return CreatedCredentialResponse(**response.model_dump(), secret=created.secret)


@router.get(
    "/credentials",
    response_model=list[CredentialMetadataResponse],
    summary="List owned CI credentials",
)
async def list_credentials(
    session: SessionDep, current_user: CurrentUser
) -> list[CredentialMetadataResponse]:
    """Credential metadata for the owner (never any secret material)."""
    return [_to_metadata(row) for row in await CiService(session, current_user).list_credentials()]


@router.post(
    "/credentials/{credential_id}/rotate",
    response_model=CreatedCredentialResponse,
    summary="Rotate a CI credential",
)
async def rotate_credential(
    credential_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> CreatedCredentialResponse:
    """Replace the secret; the old bearer dies immediately (secret shown once)."""
    created = await CiService(session, current_user).rotate_credential(credential_id)
    response = _to_metadata(
        {
            "id": created.id,
            "name": created.name,
            "target_id": created.target_id,
            "scope": "scan",
            "key_prefix": created.key_prefix,
            "created_at": created.created_at,
            "last_used_at": None,
            "expires_at": created.expires_at,
            "revoked_at": None,
        }
    )
    return CreatedCredentialResponse(**response.model_dump(), secret=created.secret)


@router.post(
    "/credentials/{credential_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a CI credential",
)
async def revoke_credential(
    credential_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> None:
    """Revoke (idempotent; foreign ids are 404, never 403)."""
    await CiService(session, current_user).revoke_credential(credential_id)


# --------------------------------------------------------------------- #
# Automation plane (bearer credential)                                   #
# --------------------------------------------------------------------- #


@router.post(
    "/scans",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a scan on the credential's target",
)
async def trigger_scan(
    payload: TriggerScanRequest,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    """Create a normal scan through the existing pipeline (202).

    The target comes from the credential binding — the body cannot
    name a target. Retries with the same idempotency key return the
    original scan (200, ``idempotent: true``).
    """
    context = await _ci_context(request, session)
    service = CiService(session, context.owner)
    outcome = await service.trigger_scan(
        context,
        scan_profile=payload.scan_profile,
        idempotency_key=payload.idempotency_key,
        policy=payload.policy,
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK if outcome["idempotent"] else status.HTTP_202_ACCEPTED,
        content={
            "scanId": str(outcome["scan_id"]),
            "status": outcome["status"],
            "targetId": str(outcome["target_id"]),
            "idempotent": outcome["idempotent"],
            "dispatched": outcome["dispatched"],
        },
    )


@router.get("/scans/{scan_id}", summary="Poll a deterministic scan result")
async def get_scan_result(
    scan_id: uuid.UUID,
    request: Request,
    session: SessionDep,
) -> JSONResponse:
    """Bounded result + deterministic policy outcome for one scan.

    The credential sees only scans of its bound target (others 404).
    A scan success carrying a policy violation still answers 200 —
    findings are data, never a 500.
    """
    context = await _ci_context(request, session)
    service = CiService(session, context.owner)
    result = await service.get_result(context, scan_id)
    return JSONResponse(status_code=status.HTTP_200_OK, content=_json_safe(result))


def _json_safe(payload: dict[str, Any]) -> dict[str, Any]:
    import json

    decoded: dict[str, Any] = json.loads(json.dumps(payload, default=str))
    return decoded


__all__ = ["router"]

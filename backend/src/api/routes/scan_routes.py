"""Scan lifecycle endpoints (SRS Chapter 5, Section 6; ADR-0009).

All routes require authentication and are tenant-isolated server-side.
Scan creation enforces the authorization-attestation gate (403
ATTESTATION_NOT_CONFIRMED); execution runs as a background job through the
secure chain (resolver → policy → binding → sandbox → transport → engine →
AI), never from API-layer networking.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, cast

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import CurrentUser  # noqa: TC001 - FastAPI runtime
from src.config.settings import get_settings
from src.domain.scans.scan_service import ScanDetails, ScanService
from src.infrastructure.database.connection import get_db_session

router = APIRouter(prefix="/scans", tags=["Scans"])

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


# --------------------------------------------------------------------- #
# DTOs                                                                  #
# --------------------------------------------------------------------- #


class CreateScanRequest(BaseModel):
    target_id: uuid.UUID = Field(validation_alias="targetId")
    scan_profile: str = Field(
        default="standard",
        validation_alias="scanProfile",
        pattern="^(quick-check|standard|full-assessment)$",
    )


class ScanResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID = Field(serialization_alias="targetId")
    scan_profile: str = Field(serialization_alias="scanProfile")
    status: str
    initiated_by: uuid.UUID = Field(serialization_alias="initiatedBy")
    authorization_attestation_id: uuid.UUID = Field(
        serialization_alias="authorizationAttestationId"
    )
    queued_at: datetime | None = Field(serialization_alias="queuedAt")
    started_at: datetime | None = Field(serialization_alias="startedAt")
    completed_at: datetime | None = Field(serialization_alias="completedAt")
    created_at: datetime = Field(serialization_alias="createdAt")


class FindingResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    evidence: str
    location: str
    recommendation: str
    created_at: str = Field(
        validation_alias=AliasChoices("createdAt", "created_at"),
        serialization_alias="createdAt",
    )


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    available: bool
    provider: str
    model: str
    prompt_schema_version: str = Field(
        validation_alias=AliasChoices("promptSchemaVersion", "prompt_schema_version"),
        serialization_alias="promptSchemaVersion",
    )
    output_schema_version: str = Field(
        validation_alias=AliasChoices("outputSchemaVersion", "output_schema_version"),
        serialization_alias="outputSchemaVersion",
    )
    failure_kind: str | None = Field(
        validation_alias=AliasChoices("failureKind", "failure_kind"),
        serialization_alias="failureKind",
    )
    unsupported_claim_count: int = Field(
        validation_alias=AliasChoices("unsupportedClaimCount", "unsupported_claim_count"),
        serialization_alias="unsupportedClaimCount",
    )
    payload: dict[str, Any]
    created_at: str = Field(
        validation_alias=AliasChoices("createdAt", "created_at"),
        serialization_alias="createdAt",
    )


def _to_response(details: ScanDetails) -> ScanResponse:
    return ScanResponse(
        id=details.id,
        target_id=details.target_id,
        scan_profile=details.scan_profile_code,
        status=details.status_code,
        initiated_by=details.initiated_by_user_id,
        authorization_attestation_id=details.authorization_attestation_id,
        queued_at=details.queued_at,
        started_at=details.started_at,
        completed_at=details.completed_at,
        created_at=details.created_at,
    )


def _service(session: AsyncSession, current_user: Any) -> ScanService:
    return ScanService(session, current_user)


def _maybe_gemini() -> Any:
    from src.infrastructure.secrets import get_gemini_api_key

    get_settings()
    if not get_gemini_api_key():
        return None
    try:
        from src.infrastructure.ai.gemini_provider import GeminiEvidenceAnalyzer

        return GeminiEvidenceAnalyzer.from_settings()
    except Exception:  # noqa: BLE001 - AI must degrade, never block creation
        return None


# --------------------------------------------------------------------- #
# Endpoints                                                             #
# --------------------------------------------------------------------- #


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Authorize + queue a scan against an attested target",
)
async def create_scan(
    payload: CreateScanRequest,
    response_bg: BackgroundTasks,
    session: SessionDep,
    current_user: CurrentUser,
) -> ScanResponse:
    service = _service(session, current_user)
    details = await service.create_scan(
        target_id=payload.target_id,
        scan_profile_code=payload.scan_profile,
    )
    # Execution decision (ADR-0009): background jobs are scheduled ONLY when
    # the operator-enabled switch is on. Otherwise the scan remains QUEUED —
    # visible, cancellable, and never executed.
    if get_settings().scanner_execution_enabled:
        from src.workers.scan_tasks import enqueue_scan

        task_id = enqueue_scan(details.id)
        if not task_id:
            # Worker tier unavailable; fall back to in-process scheduling so
            # a single-host dev deployment still runs scans end-to-end.
            response_bg.add_task(
                service.build_background_job(details.id, ai_analyzer=_maybe_gemini())
            )
    return _to_response(details)


@router.get("", response_model=list[ScanResponse], summary="List scans (initiator scope)")
async def list_scans(
    session: SessionDep,
    current_user: CurrentUser,
    target_id: Annotated[uuid.UUID | None, Query(alias="targetId")] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ScanResponse]:
    rows = await _service(session, current_user).list_scans(
        target_id=target_id, status_code=status_filter, limit=limit
    )
    return [_to_response(row) for row in rows]


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan detail")
async def get_scan(
    scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> ScanResponse:
    details = await _service(session, current_user).get_scan(scan_id)
    return _to_response(details)


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a scan that has not started running",
)
async def cancel_scan(
    scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> ScanResponse:
    details = await _service(session, current_user).cancel_scan(scan_id)
    return _to_response(details)


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingResponse],
    summary="Deterministic findings for a completed scan",
)
async def list_findings(
    scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> list[FindingResponse]:
    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    rows = await ScanEngineExecutionRepository(session).list_finding_dtos(scan_id)
    return [FindingResponse(**row) for row in rows]  # type: ignore[arg-type]


@router.get(
    "/{scan_id}/findings/{finding_id}/explanation",
    response_model=dict[str, object],
    summary="Per-finding AI explanation (validated or fallback template)",
)
async def get_finding_explanation(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> dict[str, object]:
    """Return the AI explanation for one finding.

    The endpoint is honest about provenance: a finding without an
    explanation is served a deterministic fallback template (NEVER a 404
    or an empty body) so the user always gets a readable explanation.
    The ``validationStatus`` field of the response is the single
    boolean the UI needs to label the answer correctly.
    """
    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate
    from src.domain.scanning.analysis.fallback_templates import (
        build_fallback_explanation,
    )
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    repository = ScanEngineExecutionRepository(session)
    finding_dto = await repository.get_finding_with_evidence(finding_id)
    if finding_dto is None:
        return {
            "available": False,
            "validationStatus": "FALLBACK_USED",
            "fallbackReason": "finding_not_found",
        }

    # Confirm the finding belongs to this scan (cross-scan isolation).
    findings_in_scan = await repository.list_finding_dtos(scan_id)
    if not any(str(row["id"]) == str(finding_id) for row in findings_in_scan):
        return {
            "available": False,
            "validationStatus": "FALLBACK_USED",
            "fallbackReason": "finding_not_in_scan",
        }

    assessment = await repository.get_assessment(scan_id)
    if assessment is None or not assessment.is_available:
        # AI is unavailable, didn't run, or produced a failed response:
        # always return a fallback so the user sees deterministic content.
        explanation = build_fallback_explanation(
            finding_id=str(finding_id),
            category_code=str(finding_dto.get("category", "")),
        )
        return {
            "available": True,
            "validationStatus": explanation.validation_status.value,
            "explanation": explanation.to_dict(),
        }

    # AI output is available: emit the assessment's per-finding narrative
    # when it carries one, otherwise the same deterministic fallback.
    payload = dict(assessment.payload or {})
    per_finding = payload.get("findings")
    if isinstance(per_finding, dict) and str(finding_id) in per_finding:
        return {
            "available": True,
            "validationStatus": "validated",
            "explanation": per_finding[str(finding_id)],
        }

    explanation = build_fallback_explanation(
        finding_id=str(finding_id),
        category_code=str(finding_dto.get("category", "")),
    )
    return {
        "available": True,
        "validationStatus": explanation.validation_status.value,
        "explanation": explanation.to_dict(),
    }


@router.get(
    "/{scan_id}/report",
    summary="Render the canonical report for one scan in the requested format",
    responses={
        200: {
            "description": "Report rendered in the requested format.",
            "content": {
                "application/json": {},
                "text/csv": {},
            },
        },
        404: {"description": "Scan not found."},
        422: {"description": "Unsupported format."},
    },
)
async def render_scan_report(
    scan_id: uuid.UUID,
    format: Annotated[  # noqa: A002 - public API name
        str,
        Query(pattern="^(json|csv)$", description="Report format: json or csv"),
    ] = "json",
    session: SessionDep = None,  # type: ignore[assignment]
    current_user: CurrentUser = None,  # type: ignore[assignment]
) -> Response:
    """Render the report for one scan as JSON or CSV (SRS Ch10 §4).

    The renderer is read-only: it never mutates any database state and
    never alters the canonical finding/severity/lifecycle values
    established by the scan pipeline (Ch10 §3 integrity constraint).
    """
    from fastapi.responses import JSONResponse, PlainTextResponse

    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate

    from src.reporting.assembler import ReportAssembler
    from src.reporting.export_formatters.csv_formatter import render_csv_report
    from src.reporting.export_formatters.json_formatter import render_json_report

    document = await ReportAssembler(session).assemble(scan_id)
    if document is None:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "Scan not found."}},
        )

    if format == "json":
        body = render_json_report(document)
        return JSONResponse(
            status_code=200,
            content=json.loads(body),
        )
    body = render_csv_report(document)
    return PlainTextResponse(content=body, media_type="text/csv; charset=utf-8")


@router.get(
    "/{scan_id}/assessment",
    response_model=AssessmentResponse | dict[str, str],
    summary="AI assessment for a scan (or controlled unavailability)",
)
async def get_assessment(scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser) -> Any:
    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    dto = await ScanEngineExecutionRepository(session).get_assessment_dto(scan_id)
    if dto is None:
        return {
            "available": False,
            "provider": "none",
            "model": "none",
            "promptSchemaVersion": "v1",
            "outputSchemaVersion": "v1",
            "failureKind": "not_ready",
            "unsupportedClaimCount": 0,
            "payload": {},
            "createdAt": datetime.now(UTC).isoformat(),
        }
    return AssessmentResponse(
        available=bool(dto["available"]),
        provider=str(dto["provider"]),
        model=str(dto["model"]),
        prompt_schema_version=str(dto["promptSchemaVersion"]),
        output_schema_version=str(dto["outputSchemaVersion"]),
        failure_kind=cast("str | None", dto["failureKind"]),
        unsupported_claim_count=int(str(dto["unsupportedClaimCount"])),
        payload=cast("dict[str, Any]", dto["payload"]),
        created_at=str(dto["createdAt"]),
    )


@router.post(
    "/{scan_id}/rescan",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan linked to a previous scan (rescan)",
)
async def rescan_scan(
    scan_id: uuid.UUID,
    response_bg: BackgroundTasks,
    session: SessionDep,
    current_user: CurrentUser,
) -> ScanResponse:
    service = _service(session, current_user)
    new_details = await service.rescan_scan(scan_id)
    if get_settings().scanner_execution_enabled:
        from src.workers.scan_tasks import enqueue_scan

        task_id = enqueue_scan(new_details.id)
        if not task_id:
            response_bg.add_task(
                service.build_background_job(new_details.id, ai_analyzer=_maybe_gemini())
            )
    return _to_response(new_details)


class FindingCompareItem(BaseModel):
    id: str
    fingerprint: str
    title: str


class CompareResponse(BaseModel):
    new_: list[FindingCompareItem] = Field(alias="new")
    persistent: list[FindingCompareItem]
    resolved: list[FindingCompareItem]
    regressed: list[FindingCompareItem]

    model_config = {"populate_by_name": True}


@router.get(
    "/{scan_a_id}/compare/{scan_b_id}",
    response_model=CompareResponse,
    summary="Compare findings between two scans of the same target",
)
async def compare_scans(
    scan_a_id: uuid.UUID,
    scan_b_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> CompareResponse:
    result = await _service(session, current_user).compare_scans(scan_a_id, scan_b_id)
    return CompareResponse(
        new=[
            FindingCompareItem(
                id=str(i["id"]), fingerprint=str(i["fingerprint"]), title=str(i["title"])
            )
            for i in result["new"]
        ],
        persistent=[
            FindingCompareItem(
                id=str(i["id"]), fingerprint=str(i["fingerprint"]), title=str(i["title"])
            )
            for i in result["persistent"]
        ],
        resolved=[
            FindingCompareItem(
                id=str(i["id"]), fingerprint=str(i["fingerprint"]), title=str(i["title"])
            )
            for i in result["resolved"]
        ],
        regressed=[
            FindingCompareItem(
                id=str(i["id"]), fingerprint=str(i["fingerprint"]), title=str(i["title"])
            )
            for i in result["regressed"]
        ],
    )

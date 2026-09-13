"""Compliance evidence-mapping endpoints (read-only derived layer).

Every assessment derives from the caller's own scans, findings, and
workflow state — cross-owner ids answer 404 through the existing
visibility gates. Nothing here certifies compliance: statuses report
control relevance and gap evidence only (see the assessment
disclaimer returned with every payload).
"""

from __future__ import annotations

import uuid  # noqa: TC003 - FastAPI resolves route annotations at runtime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.compliance.service import ComplianceService

router = APIRouter(prefix="/compliance", tags=["Compliance"])


class FrameworkResponse(BaseModel):
    """Framework catalog entry (global, identical for every user)."""

    framework_id: str = Field(serialization_alias="frameworkId")
    name: str
    version: str
    source: str
    mapping_version: str = Field(serialization_alias="mappingVersion")
    control_count: int = Field(serialization_alias="controlCount")


class ControlResponse(BaseModel):
    """One curated control with its mapped finding categories."""

    framework_id: str = Field(serialization_alias="frameworkId")
    control_id: str = Field(serialization_alias="controlId")
    title: str
    description: str
    rationale: str
    mapped_categories: list[str] = Field(serialization_alias="mappedCategories")


def _service(session: Any, current_user: Any) -> ComplianceService:
    return ComplianceService(session, current_user)


def _str(value: object) -> str:
    assert isinstance(value, str)
    return value


def _str_list(value: object) -> list[str]:
    assert isinstance(value, list)
    return [str(item) for item in value]


def _int(value: object) -> int:
    assert isinstance(value, int)
    return value


@router.get("/frameworks", response_model=list[FrameworkResponse], summary="List frameworks")
async def list_frameworks(
    session: SessionDep, current_user: CurrentUser
) -> list[FrameworkResponse]:
    """Curated framework catalog (global seed, no per-user state)."""
    return [
        FrameworkResponse(
            framework_id=_str(row["framework_id"]),
            name=str(row["name"]),
            version=str(row["version"]),
            source=str(row["source"]),
            mapping_version=str(row["mapping_version"]),
            control_count=_int(row["control_count"]),
        )
        for row in await _service(session, current_user).list_frameworks()
    ]


@router.get(
    "/frameworks/{framework_id}",
    response_model=FrameworkResponse,
    summary="Get framework detail",
)
async def get_framework(
    framework_id: str, session: SessionDep, current_user: CurrentUser
) -> FrameworkResponse:
    """One framework with its control count (unknown ids are 404)."""
    row = await _service(session, current_user).get_framework(framework_id)
    return FrameworkResponse(
        framework_id=_str(row["framework_id"]),
        name=str(row["name"]),
        version=str(row["version"]),
        source=str(row["source"]),
        mapping_version=str(row["mapping_version"]),
        control_count=_int(row["control_count"]),
    )


@router.get(
    "/frameworks/{framework_id}/controls",
    response_model=list[ControlResponse],
    summary="List framework controls",
)
async def list_controls(
    framework_id: str, session: SessionDep, current_user: CurrentUser
) -> list[ControlResponse]:
    """Curated controls with mapped categories, stable control-id order."""
    return [
        ControlResponse(
            framework_id=_str(row["framework_id"]),
            control_id=str(row["control_id"]),
            title=str(row["title"]),
            description=str(row["description"]),
            rationale=str(row["rationale"]),
            mapped_categories=_str_list(row["mapped_categories"]),
        )
        for row in await _service(session, current_user).list_controls(framework_id)
    ]


@router.get(
    "/frameworks/{framework_id}/controls/{control_id}",
    response_model=ControlResponse,
    summary="Get control detail",
)
async def get_control(
    framework_id: str,
    control_id: str,
    session: SessionDep,
    current_user: CurrentUser,
) -> ControlResponse:
    """One control with rationale (unknown ids are 404)."""
    row = await _service(session, current_user).get_control(framework_id, control_id)
    return ControlResponse(
        framework_id=_str(row["framework_id"]),
        control_id=str(row["control_id"]),
        title=str(row["title"]),
        description=str(row["description"]),
        rationale=str(row["rationale"]),
        mapped_categories=_str_list(row["mapped_categories"]),
    )


@router.get(
    "/frameworks/{framework_id}/assessment",
    summary="Assess a framework over owned evidence",
)
async def assess_framework(
    framework_id: str,
    session: SessionDep,
    current_user: CurrentUser,
    scan_id: Annotated[uuid.UUID | None, Query(alias="scanId")] = None,
    target_id: Annotated[uuid.UUID | None, Query(alias="targetId")] = None,
    format: Annotated[str, Query()] = "json",  # noqa: A002 - query name is the contract
) -> Response:
    """Evidence mapping for one framework (JSON default, CSV on request).

    Scope is one scan, one target, or the whole account (scan and
    target together are 400). Foreign ids are 404. Every response
    carries the mapping version and the not-a-certification
    disclaimer; CSV neutralizes formula prefixes in free-text cells.
    """
    from src.domain.compliance.assessment import assessment_to_csv

    requested = format.strip().lower()
    if requested not in ("json", "csv"):
        from src.domain.compliance.errors import InvalidComplianceError

        raise InvalidComplianceError("format must be 'json' or 'csv'.")
    assessment = await _service(session, current_user).assess(
        framework_id, scan_id=scan_id, target_id=target_id
    )
    if requested == "csv":
        return PlainTextResponse(
            assessment_to_csv(assessment),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=compliance-assessment.csv"},
        )
    return Response(
        content=_dumps(assessment),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=compliance-assessment.json"},
    )


def _dumps(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)

"""Report data assembler: format-agnostic, pure read step (SRS Ch10 §1).

The assembler pulls one canonical, fully-resolved data structure from
the database for a single scan. Every format-specific renderer (JSON,
CSV, future PDF) consumes the SAME structure, so the three output
formats can never drift into showing inconsistent data.

Integrity contract (Ch10 §3): the assembler is a pure read/render step.
It never reinterprets, recomputes, or overrides the deterministic
severity, lifecycle status, or finding identity that the scan pipeline
already established.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


REPORT_SCHEMA_VERSION = "sgpt.report.v1"


@dataclass(frozen=True)
class ReportScanMetadata:
    target_hostname: str
    target_normalized_url: str
    scan_id: uuid.UUID
    scan_profile: str
    scan_status: str
    initiated_by_user_id: uuid.UUID
    queued_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None


@dataclass(frozen=True)
class ReportEngineSummary:
    engine_code: str
    tool_version_snapshot: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None


@dataclass(frozen=True)
class ReportFinding:
    id: uuid.UUID
    severity: str
    category: str
    title: str
    description: str
    evidence: str
    location: str
    recommendation: str
    fingerprint: str | None
    affected_asset: str | None
    source_engine_code: str | None
    evidence_rows: tuple[dict[str, object], ...] = field(default=())
    explanation: dict[str, object] | None = None


@dataclass(frozen=True)
class ReportAssessment:
    available: bool
    provider: str
    model: str
    prompt_schema_version: str
    output_schema_version: str
    failure_kind: str | None
    unsupported_claim_count: int
    overall_summary: str
    priority: str | None
    payload: dict[str, object]


@dataclass(frozen=True)
class ReportDocument:
    """The one canonical structure every renderer consumes."""

    schema_version: str
    generated_at: datetime
    scan: ReportScanMetadata
    engines: tuple[ReportEngineSummary, ...]
    findings: tuple[ReportFinding, ...]
    assessment: ReportAssessment | None
    severity_counts: dict[str, int]
    lifecycle_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at.isoformat(),
            "scan": {
                "id": str(self.scan.scan_id),
                "target_hostname": self.scan.target_hostname,
                "target_normalized_url": self.scan.target_normalized_url,
                "scan_profile": self.scan.scan_profile,
                "status": self.scan.scan_status,
                "initiated_by_user_id": str(self.scan.initiated_by_user_id),
                "queued_at": self.scan.queued_at.isoformat() if self.scan.queued_at else None,
                "started_at": self.scan.started_at.isoformat() if self.scan.started_at else None,
                "completed_at": self.scan.completed_at.isoformat()
                if self.scan.completed_at
                else None,
            },
            "engines": [
                {
                    "engine_code": e.engine_code,
                    "tool_version_snapshot": e.tool_version_snapshot,
                    "status": e.status,
                    "started_at": e.started_at.isoformat() if e.started_at else None,
                    "completed_at": e.completed_at.isoformat() if e.completed_at else None,
                    "error_message": e.error_message,
                }
                for e in self.engines
            ],
            "severity_counts": dict(sorted(self.severity_counts.items())),
            "lifecycle_counts": dict(sorted(self.lifecycle_counts.items())),
            "findings": [
                {
                    "id": str(f.id),
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "location": f.location,
                    "recommendation": f.recommendation,
                    "fingerprint": f.fingerprint,
                    "affected_asset": f.affected_asset,
                    "source_engine_code": f.source_engine_code,
                    "evidence_rows": list(f.evidence_rows),
                    "explanation": f.explanation,
                }
                for f in self.findings
            ],
            "assessment": {
                "available": self.assessment.available,
                "provider": self.assessment.provider,
                "model": self.assessment.model,
                "prompt_schema_version": self.assessment.prompt_schema_version,
                "output_schema_version": self.assessment.output_schema_version,
                "failure_kind": self.assessment.failure_kind,
                "unsupported_claim_count": self.assessment.unsupported_claim_count,
                "overall_summary": self.assessment.overall_summary,
                "priority": self.assessment.priority,
                "payload": self.assessment.payload,
            }
            if self.assessment is not None
            else None,
        }


class ReportAssembler:
    """Pure read step: scan + findings + assessment → ReportDocument.

    Tenant isolation is enforced at the caller (the service layer calls
    ``get_scan`` first to verify the principal can see the scan). The
    assembler itself never raises authorization errors.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def assemble(self, scan_id: uuid.UUID) -> ReportDocument | None:
        """Return the canonical report, or None if the scan does not exist."""
        from src.infrastructure.database.models import Scan, Target

        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            return None

        target = await self._session.get(Target, scan.target_id)
        target_hostname = getattr(target, "hostname", "") if target is not None else ""
        target_normalized_url = (
            getattr(target, "normalized_url", "") if target is not None else ""
        )

        profile_code = await self._profile_code(scan.scan_profile_id)
        status_code = await self._status_code(scan.status_id)

        engines = await self._engines(scan_id)
        findings = await self._findings(scan_id)
        assessment = await self._assessment(scan_id)
        fingerprints = [f.fingerprint for f in findings]
        lifecycle_counts = await self._lifecycle_counts(
            scan.target_id, fingerprints
        )

        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return ReportDocument(
            schema_version=REPORT_SCHEMA_VERSION,
            generated_at=datetime.now(UTC),
            scan=ReportScanMetadata(
                target_hostname=target_hostname,
                target_normalized_url=target_normalized_url,
                scan_id=scan.id,
                scan_profile=profile_code,
                scan_status=status_code,
                initiated_by_user_id=scan.initiated_by_user_id,
                queued_at=scan.queued_at,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
            ),
            engines=engines,
            findings=findings,
            assessment=assessment,
            severity_counts=severity_counts,
            lifecycle_counts=lifecycle_counts,
        )

    async def _profile_code(self, profile_id: int) -> str:
        from sqlalchemy import select

        from src.infrastructure.database.models import ScanProfile

        row = (
            await self._session.execute(
                select(ScanProfile.code).where(ScanProfile.id == profile_id)
            )
        ).first()
        return str(row[0]) if row is not None else "unknown"

    async def _status_code(self, status_id: int) -> str:
        from sqlalchemy import select

        from src.infrastructure.database.models import ScanStatus

        row = (
            await self._session.execute(
                select(ScanStatus.code).where(ScanStatus.id == status_id)
            )
        ).first()
        return str(row[0]) if row is not None else "unknown"

    async def _engines(
        self, scan_id: uuid.UUID
    ) -> tuple[ReportEngineSummary, ...]:
        from sqlalchemy import select

        from src.infrastructure.database.models import (
            ScanEngine,
            ScanEngineExecution,
        )

        rows = await self._session.execute(
            select(
                ScanEngine.code,
                ScanEngineExecution.tool_version_snapshot,
                ScanEngineExecution.status,
                ScanEngineExecution.started_at,
                ScanEngineExecution.completed_at,
                ScanEngineExecution.error_message,
            )
            .join(ScanEngine, ScanEngineExecution.scan_engine_id == ScanEngine.id)
            .where(ScanEngineExecution.scan_id == scan_id)
            .order_by(ScanEngineExecution.started_at.asc().nullslast())
        )
        return tuple(
            ReportEngineSummary(
                engine_code=row.code,
                tool_version_snapshot=row.tool_version_snapshot,
                status=row.status,
                started_at=row.started_at,
                completed_at=row.completed_at,
                error_message=row.error_message,
            )
            for row in rows.all()
        )

    async def _findings(
        self, scan_id: uuid.UUID
    ) -> tuple[ReportFinding, ...]:
        from sqlalchemy import select

        from src.infrastructure.database.models import (
            FindingCategory,
            FindingEvidence,
            ScanEngineExecution,
            ScanFinding,
            SeverityLevel,
        )

        rows = await self._session.execute(
            select(
                ScanFinding.id,
                ScanFinding.title,
                ScanFinding.description,
                ScanFinding.evidence,
                ScanFinding.location,
                ScanFinding.recommendation,
                ScanFinding.fingerprint,
                ScanFinding.affected_asset,
                ScanFinding.source_engine_code,
                FindingCategory.code.label("category_code"),
                SeverityLevel.code.label("severity_code"),
            )
            .join(
                ScanEngineExecution,
                ScanFinding.execution_id == ScanEngineExecution.id,
            )
            .join(FindingCategory, ScanFinding.category_id == FindingCategory.id)
            .join(SeverityLevel, ScanFinding.severity_id == SeverityLevel.id)
            .where(ScanEngineExecution.scan_id == scan_id)
            .order_by(ScanFinding.created_at.asc())
        )

        result: list[ReportFinding] = []
        for row in rows.all():
            evidence_rows = await self._session.execute(
                select(
                    FindingEvidence.id,
                    FindingEvidence.evidence_type,
                    FindingEvidence.content,
                )
                .where(FindingEvidence.finding_id == row.id)
                .order_by(FindingEvidence.created_at.asc())
            )
            ev = [
                {
                    "id": str(e.id),
                    "type": e.evidence_type,
                    "content": e.content,
                }
                for e in evidence_rows.all()
            ]
            result.append(
                ReportFinding(
                    id=row.id,
                    severity=row.severity_code,
                    category=row.category_code,
                    title=row.title,
                    description=row.description,
                    evidence=row.evidence,
                    location=row.location,
                    recommendation=row.recommendation,
                    fingerprint=row.fingerprint,
                    affected_asset=row.affected_asset,
                    source_engine_code=row.source_engine_code,
                    evidence_rows=tuple(ev),
                    explanation=None,
                )
            )
        return tuple(result)

    async def _assessment(
        self, scan_id: uuid.UUID
    ) -> ReportAssessment | None:
        from sqlalchemy import select

        from src.infrastructure.database.models import (
            ScanAiAssessment,
            ScanEngineExecution,
        )

        row = (
            await self._session.execute(
                select(
                    ScanAiAssessment.is_available,
                    ScanAiAssessment.provider,
                    ScanAiAssessment.model,
                    ScanAiAssessment.prompt_schema_version,
                    ScanAiAssessment.output_schema_version,
                    ScanAiAssessment.failure_kind,
                    ScanAiAssessment.unsupported_claim_count,
                    ScanAiAssessment.payload,
                )
                .join(
                    ScanEngineExecution,
                    ScanAiAssessment.execution_id == ScanEngineExecution.id,
                )
                .where(ScanEngineExecution.scan_id == scan_id)
                .order_by(ScanAiAssessment.created_at.desc())
                .limit(1)
            )
        ).first()
        if row is None:
            return None
        payload = dict(row.payload or {})
        overall_summary = str(payload.get("overall_summary", ""))
        priority = payload.get("priority")
        return ReportAssessment(
            available=bool(row.is_available),
            provider=row.provider,
            model=row.model,
            prompt_schema_version=row.prompt_schema_version,
            output_schema_version=row.output_schema_version,
            failure_kind=row.failure_kind,
            unsupported_claim_count=int(row.unsupported_claim_count),
            overall_summary=overall_summary,
            priority=str(priority) if priority is not None else None,
            payload=payload,
        )

    async def _lifecycle_counts(
        self,
        target_id: uuid.UUID,
        fingerprints: list[str | None],
    ) -> dict[str, int]:
        from sqlalchemy import select

        from src.infrastructure.database.models import (
            FindingLifecycleStatus,
            FindingStatusHistory,
        )

        fps = [fp for fp in fingerprints if fp]
        if not fps:
            return {}
        rows = await self._session.execute(
            select(
                FindingStatusHistory.fingerprint,
                FindingStatusHistory.finding_lifecycle_status_id,
            )
            .where(
                FindingStatusHistory.target_id == target_id,
                FindingStatusHistory.fingerprint.in_(fps),
            )
            .order_by(FindingStatusHistory.effective_at.desc())
        )
        status_rows = await self._session.execute(
            select(FindingLifecycleStatus.id, FindingLifecycleStatus.code)
        )
        id_to_code = {int(i): c for i, c in status_rows.all()}
        latest: dict[str, str] = {}
        for fp, sid in rows.all():
            if fp in latest:
                continue
            latest[fp] = id_to_code.get(int(sid), "")
        counts: dict[str, int] = {}
        for code in latest.values():
            counts[code] = counts.get(code, 0) + 1
        return counts


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "ReportAssembler",
    "ReportAssessment",
    "ReportDocument",
    "ReportEngineSummary",
    "ReportFinding",
    "ReportScanMetadata",
]

"""Scan repository: lifecycle persistence + optimistic state transitions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from src.infrastructure.database.models import (
    Scan,
    ScanAiAssessment,
    ScanEngineExecution,
    ScanFinding,
    ScanStatus,
)

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


class ScanRepository:
    """Data-access boundary for the ``scan`` aggregate."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, scan: Scan) -> None:
        self._session.add(scan)

    async def flush(self) -> None:
        await self._session.flush()

    async def get_by_id(self, scan_id: uuid.UUID) -> Scan | None:
        return await self._session.get(Scan, scan_id)

    async def list_for_user(
        self,
        user_id: uuid.UUID,
        *,
        target_id: uuid.UUID | None = None,
        status_code: str | None = None,
        limit: int = 50,
    ) -> list[Scan]:
        """Scans initiated by this user (tenant-isolated listing baseline)."""
        from src.infrastructure.database.models import ScanStatus

        stmt = (
            select(Scan)
            .join(ScanStatus, Scan.status_id == ScanStatus.id)
            .where(Scan.initiated_by_user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        if target_id is not None:
            stmt = stmt.where(Scan.target_id == target_id)
        if status_code is not None:
            stmt = stmt.where(ScanStatus.code == status_code)
        rows = await self._session.execute(stmt)
        return list(rows.scalars().all())

    # ------------------------------------------------------------------ #
    # Optimistic state transitions (concurrency-safe by construction)     #
    # ------------------------------------------------------------------ #

    async def try_transition(
        self,
        scan_id: uuid.UUID,
        *,
        from_status_id: int,
        to_status_id: int,
        set_started_at: datetime | None = None,
        set_completed_at: datetime | None = None,
    ) -> bool:
        """Atomically move scan only when it is still in ``from_status_id``.

        Returns False when another worker already transitioned the row —
        the caller must then abort instead of double-executing.
        """
        values: dict[str, object] = {"status_id": to_status_id}
        if set_started_at is not None:
            values["started_at"] = set_started_at
        if set_completed_at is not None:
            values["completed_at"] = set_completed_at
        result = await self._session.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status_id == from_status_id)
            .values(**values)
        )
        rowcount = getattr(result, "rowcount", 0)
        return int(rowcount) == 1

    async def status_ids_by_code(self) -> dict[str, int]:
        rows = await self._session.execute(select(ScanStatus.id, ScanStatus.code))
        mapping: dict[str, int] = {}
        for id_, code in rows:
            mapping[code] = id_
        return mapping


async def _status_code_of(session: AsyncSession, status_id: int) -> str:
    from src.infrastructure.database.models import ScanStatus

    row = (await session.execute(select(ScanStatus.code).where(ScanStatus.id == status_id))).first()
    if row is None:
        raise LookupError(f"scan_status id {status_id} not seeded")
    return str(row[0])


async def _profile_id(session: AsyncSession, code: str) -> int:
    from src.infrastructure.database.models import ScanProfile

    row = (await session.execute(select(ScanProfile.id).where(ScanProfile.code == code))).first()
    if row is None:
        raise LookupError(f"scan_profile {code!r} is not seeded")
    return int(row[0])


async def _profile_code(session: AsyncSession, profile_id: int) -> str:
    from src.infrastructure.database.models import ScanProfile

    row = (
        await session.execute(select(ScanProfile.code).where(ScanProfile.id == profile_id))
    ).first()
    if row is None:
        raise LookupError(f"scan_profile id {profile_id} not seeded")
    return str(row[0])


class ScanEngineExecutionRepository:
    """Persistence for engine-execution rows and their children."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        scan_id: uuid.UUID,
        scan_engine_id: int,
        tool_version_snapshot: str,
        status: str = "PENDING",
        started_at: datetime | None = None,
    ) -> ScanEngineExecution:
        execution = ScanEngineExecution(
            scan_id=scan_id,
            scan_engine_id=scan_engine_id,
            tool_version_snapshot=tool_version_snapshot,
            status=status,
            started_at=started_at,
        )
        self._session.add(execution)
        await self._session.flush()
        return execution

    async def mark(
        self,
        execution_id: uuid.UUID,
        *,
        status: str,
        completed_at: datetime,
        error_message: str | None = None,
    ) -> None:
        await self._session.execute(
            update(ScanEngineExecution)
            .where(ScanEngineExecution.id == execution_id)
            .values(status=status, completed_at=completed_at, error_message=error_message)
        )

    async def add_findings(self, findings: list[ScanFinding]) -> None:
        for finding in findings:
            self._session.add(finding)
        await self._session.flush()

    async def upsert_ai_assessment(
        self,
        *,
        execution_id: uuid.UUID,
        provider: str,
        model: str,
        prompt_schema_version: str,
        output_schema_version: str,
        is_available: bool,
        failure_kind: str | None,
        unsupported_claim_count: int,
        payload: dict[str, object],
    ) -> None:
        existing = (
            (
                await self._session.execute(
                    select(ScanAiAssessment).where(ScanAiAssessment.execution_id == execution_id)
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            for key, value in {
                "provider": provider,
                "model": model,
                "prompt_schema_version": prompt_schema_version,
                "output_schema_version": output_schema_version,
                "is_available": is_available,
                "failure_kind": failure_kind,
                "unsupported_claim_count": unsupported_claim_count,
                "payload": payload,
            }.items():
                setattr(existing, key, value)
            return
        self._session.add(
            ScanAiAssessment(
                execution_id=execution_id,
                provider=provider,
                model=model,
                prompt_schema_version=prompt_schema_version,
                output_schema_version=output_schema_version,
                is_available=is_available,
                failure_kind=failure_kind,
                unsupported_claim_count=unsupported_claim_count,
                payload=payload,
            )
        )
        await self._session.flush()

    async def list_findings(self, scan_id: uuid.UUID) -> list[ScanFinding]:
        rows = await self._session.execute(
            select(ScanFinding)
            .join(
                ScanEngineExecution,
                ScanFinding.execution_id == ScanEngineExecution.id,
            )
            .where(ScanEngineExecution.scan_id == scan_id)
            .order_by(ScanFinding.created_at.asc())
        )
        return list(rows.scalars().all())

    async def get_assessment(self, scan_id: uuid.UUID) -> ScanAiAssessment | None:
        rows = await self._session.execute(
            select(ScanAiAssessment)
            .join(
                ScanEngineExecution,
                ScanAiAssessment.execution_id == ScanEngineExecution.id,
            )
            .where(ScanEngineExecution.scan_id == scan_id)
            .order_by(ScanAiAssessment.created_at.desc())
            .limit(1)
        )
        return rows.scalars().first()

    # ------------------------------------------------------------------ #
    # Read DTOs (joined code lookups for the API layer)                  #
    # ------------------------------------------------------------------ #

    async def list_finding_dtos(self, scan_id: uuid.UUID) -> list[dict[str, object]]:
        from src.infrastructure.database.models import (
            FindingCategory,
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
                SeverityLevel.code,
                ScanFinding.created_at,
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
        return [
            {
                "id": str(row.id),
                "title": row.title,
                "description": row.description,
                "evidence": row.evidence,
                "location": row.location,
                "recommendation": row.recommendation,
                "severity": row.code,
                "createdAt": row.created_at.isoformat(),
            }
            for row in rows.all()
        ]

    async def get_finding_with_evidence(
        self, finding_id: uuid.UUID
    ) -> dict[str, object] | None:
        """One finding joined with its evidence rows + canonical category.

        The category code is the persisted DB code (post
        ``scan_service._map_category``), which is the same key the
        fallback templates are registered against.
        """
        from src.infrastructure.database.models import (
            FindingCategory,
            FindingEvidence,
            SeverityLevel,
        )

        finding_row = (
            await self._session.execute(
                select(
                    ScanFinding.id,
                    ScanFinding.title,
                    ScanFinding.description,
                    ScanFinding.evidence,
                    ScanFinding.location,
                    ScanFinding.recommendation,
                    SeverityLevel.code.label("severity_code"),
                    FindingCategory.code.label("category_code"),
                )
                .join(
                    ScanEngineExecution,
                    ScanFinding.execution_id == ScanEngineExecution.id,
                )
                .join(FindingCategory, ScanFinding.category_id == FindingCategory.id)
                .join(SeverityLevel, ScanFinding.severity_id == SeverityLevel.id)
                .where(ScanFinding.id == finding_id)
            )
        ).first()
        if finding_row is None:
            return None

        evidence_rows = await self._session.execute(
            select(
                FindingEvidence.id,
                FindingEvidence.evidence_type,
                FindingEvidence.content,
            )
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(FindingEvidence.created_at.asc())
        )
        evidence = [
            {
                "id": str(ev.id),
                "type": ev.evidence_type,
                "content": ev.content,
            }
            for ev in evidence_rows.all()
        ]
        return {
            "id": str(finding_row.id),
            "title": finding_row.title,
            "description": finding_row.description,
            "evidence": finding_row.evidence,
            "location": finding_row.location,
            "recommendation": finding_row.recommendation,
            "severity": finding_row.severity_code,
            "category": finding_row.category_code,
            "evidence_rows": evidence,
        }

    async def get_assessment_dto(self, scan_id: uuid.UUID) -> dict[str, object] | None:
        row = await self.get_assessment(scan_id)
        if row is None:
            return None
        return {
            "provider": row.provider,
            "model": row.model,
            "promptSchemaVersion": row.prompt_schema_version,
            "outputSchemaVersion": row.output_schema_version,
            "available": row.is_available,
            "failureKind": row.failure_kind,
            "unsupportedClaimCount": row.unsupported_claim_count,
            "payload": row.payload,
            "createdAt": row.created_at.isoformat(),
        }

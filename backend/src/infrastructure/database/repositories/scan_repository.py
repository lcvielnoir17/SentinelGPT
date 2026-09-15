"""Scan repository: lifecycle persistence + optimistic state transitions."""

from __future__ import annotations

import uuid
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
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.infrastructure.database.models import FindingEnrichment, FindingRemediation


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

    async def lock_owner(self, user_id: uuid.UUID) -> None:
        """Take a row lock on the user so concurrent creations serialize.

        Creation admission (active-scan counts below) is read-then-write;
        without this lock two racing ``POST /scans`` requests could both
        pass the caps. The lock is held to commit by the caller.
        """
        from sqlalchemy import select

        from src.infrastructure.database.models import User

        await self._session.execute(select(User.id).where(User.id == user_id).with_for_update())

    async def count_active_for_user(self, user_id: uuid.UUID) -> dict[str, int]:
        """Active (QUEUED/RUNNING) scan counts for one user in a single query."""
        from sqlalchemy import func

        from src.infrastructure.database.models import ScanStatus

        rows = await self._session.execute(
            select(ScanStatus.code, func.count(Scan.id))
            .join(Scan, Scan.status_id == ScanStatus.id)
            .where(
                Scan.initiated_by_user_id == user_id,
                ScanStatus.code.in_(["QUEUED", "RUNNING"]),
            )
            .group_by(ScanStatus.code)
        )
        return {str(code): int(count) for code, count in rows.all()}

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

    async def status_code_by_id(self) -> dict[int, str]:
        """Inverse of :meth:`status_ids_by_code` for batched list hydration."""
        rows = await self._session.execute(select(ScanStatus.id, ScanStatus.code))
        return {int(id_): str(code) for id_, code in rows}

    async def list_stale_running(self, *, older_than: datetime, limit: int = 100) -> list[Scan]:
        """RUNNING rows started before the cutoff (hard worker-loss candidates).

        Rows without ``started_at`` are never returned: staleness cannot
        be proven for them, so they are left for an operator.
        """
        ids = await self.status_ids_by_code()
        rows = await self._session.execute(
            select(Scan)
            .where(Scan.status_id == ids["RUNNING"], Scan.started_at < older_than)
            .order_by(Scan.started_at.asc())
            .limit(limit)
        )
        return list(rows.scalars().all())

    async def profile_code_by_id(self) -> dict[int, str]:
        """Profile code per id (one query; avoids per-row lookups in lists)."""
        from src.infrastructure.database.models import ScanProfile

        rows = await self._session.execute(select(ScanProfile.id, ScanProfile.code))
        return {int(id_): str(code) for id_, code in rows}


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

    async def list_enrichment(
        self, *, fingerprint: str, target_id: uuid.UUID
    ) -> list[dict[str, object]]:
        """Advisory enrichment rows for one fingerprint, oldest first."""
        from src.infrastructure.database.models import FindingEnrichment

        rows = await self._session.execute(
            select(FindingEnrichment)
            .where(
                FindingEnrichment.fingerprint == fingerprint,
                FindingEnrichment.target_id == target_id,
            )
            .order_by(FindingEnrichment.created_at.asc())
        )
        return [self._enrichment_dto(row) for row in rows.scalars().all()]

    async def list_enrichment_for_fingerprints(
        self, *, fingerprints: list[str], target_id: uuid.UUID
    ) -> dict[str, list[dict[str, object]]]:
        """Batched enrichment for a whole report (no per-finding N+1)."""
        from src.infrastructure.database.models import FindingEnrichment

        fps = [fp for fp in fingerprints if fp]
        if not fps:
            return {}
        rows = await self._session.execute(
            select(FindingEnrichment)
            .where(
                FindingEnrichment.fingerprint.in_(fps),
                FindingEnrichment.target_id == target_id,
            )
            .order_by(FindingEnrichment.created_at.asc())
        )
        grouped: dict[str, list[dict[str, object]]] = {}
        for row in rows.scalars().all():
            grouped.setdefault(row.fingerprint, []).append(self._enrichment_dto(row))
        return grouped

    async def add_enrichment(
        self,
        *,
        fingerprint: str,
        target_id: uuid.UUID,
        source: str,
        external_ref: str,
        cve_id: str | None,
        cwe_id: str | None,
        cvss_score: float | None,
        cvss_vector: str | None,
        references: list[str],
        affected_technology: str | None,
        remediation: str | None,
    ) -> dict[str, object]:
        """Attach one enrichment row, or return the existing identical row.

        Deduplication is by the (fingerprint, target, source, external_ref)
        identity: re-attaching the same advisory never creates a duplicate.
        A lost insert race resolves to the winner instead of a 500.
        """
        from sqlalchemy.exc import IntegrityError

        from src.infrastructure.database.models import FindingEnrichment

        existing = await self._session.execute(
            select(FindingEnrichment).where(
                FindingEnrichment.fingerprint == fingerprint,
                FindingEnrichment.target_id == target_id,
                FindingEnrichment.source == source,
                FindingEnrichment.external_ref == external_ref,
            )
        )
        row = existing.scalars().first()
        if row is None:
            row = FindingEnrichment(
                fingerprint=fingerprint,
                target_id=target_id,
                source=source,
                external_ref=external_ref,
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                references=list(references),
                affected_technology=affected_technology,
                remediation=remediation,
            )
            try:
                async with self._session.begin_nested():
                    self._session.add(row)
                    await self._session.flush()
            except IntegrityError:
                reselected = await self._session.execute(
                    select(FindingEnrichment).where(
                        FindingEnrichment.fingerprint == fingerprint,
                        FindingEnrichment.target_id == target_id,
                        FindingEnrichment.source == source,
                        FindingEnrichment.external_ref == external_ref,
                    )
                )
                row = reselected.scalars().first()
                if row is None:
                    raise
        return self._enrichment_dto(row)

    async def get_remediation(
        self, *, fingerprint: str, target_id: uuid.UUID
    ) -> dict[str, object] | None:
        """Operator remediation workflow state for one fingerprint, if any."""
        from src.infrastructure.database.models import FindingRemediation

        rows = await self._session.execute(
            select(FindingRemediation).where(
                FindingRemediation.fingerprint == fingerprint,
                FindingRemediation.target_id == target_id,
            )
        )
        row = rows.scalars().first()
        return self._remediation_dto(row) if row is not None else None

    async def set_remediation(
        self,
        *,
        fingerprint: str,
        target_id: uuid.UUID,
        status: str,
        notes: str | None,
        updated_by_user_id: uuid.UUID | None,
        assignee_user_id: uuid.UUID | None = None,
        assignee_set: bool = False,
        due_at: datetime | None = None,
        due_at_set: bool = False,
        assigned_by_user_id: uuid.UUID | None = None,
    ) -> dict[str, object]:
        """Upsert one remediation workflow row (fingerprint identity).

        Re-setting the same fingerprint updates status/notes in place —
        workflow state never duplicates and never touches canonical
        finding fields. Assignment and due date only change when their
        explicit ``*_set`` flags arrive (absent keys leave stored values
        alone); setting them to None clears. ``assigned_by``/``assigned_at``
        follow the assignee: stamped on (re)assign, cleared on unassign.
        A lost insert race resolves onto the winner instead of a 500.
        """
        from datetime import UTC, datetime

        from sqlalchemy.exc import IntegrityError

        from src.infrastructure.database.models import FindingRemediation

        existing = await self._session.execute(
            select(FindingRemediation).where(
                FindingRemediation.fingerprint == fingerprint,
                FindingRemediation.target_id == target_id,
            )
        )
        row = existing.scalars().first()
        now = datetime.now(UTC)
        if row is None:
            row = FindingRemediation(
                fingerprint=fingerprint,
                target_id=target_id,
                status=status,
                notes=notes,
                updated_by_user_id=updated_by_user_id,
                assignee_user_id=assignee_user_id if assignee_set else None,
                assigned_at=now if assignee_set and assignee_user_id is not None else None,
                assigned_by_user_id=(
                    assigned_by_user_id if assignee_set and assignee_user_id is not None else None
                ),
                due_at=due_at if due_at_set else None,
            )
            try:
                async with self._session.begin_nested():
                    self._session.add(row)
                    await self._session.flush()
                return self._remediation_dto(row)
            except IntegrityError:
                reselected = await self._session.execute(
                    select(FindingRemediation).where(
                        FindingRemediation.fingerprint == fingerprint,
                        FindingRemediation.target_id == target_id,
                    )
                )
                row = reselected.scalars().first()
                if row is None:
                    raise
        row.status = status
        row.notes = notes
        row.updated_by_user_id = updated_by_user_id
        if assignee_set:
            row.assignee_user_id = assignee_user_id
            if assignee_user_id is None:
                row.assigned_at = None
                row.assigned_by_user_id = None
            else:
                row.assigned_at = now
                row.assigned_by_user_id = assigned_by_user_id
        if due_at_set:
            row.due_at = due_at
        await self._session.flush()
        return self._remediation_dto(row)

    async def set_verification_link(
        self, *, fingerprint: str, target_id: uuid.UUID, scan_id: uuid.UUID
    ) -> dict[str, object] | None:
        """Link a remediation row to its verification rescan (M4).

        Returns the updated DTO, or None when no remediation row exists
        (verify-fix requires existing workflow state — the operator marks
        first, then verifies). Never touches status/notes.
        """
        from src.infrastructure.database.models import FindingRemediation

        existing = await self._session.execute(
            select(FindingRemediation).where(
                FindingRemediation.fingerprint == fingerprint,
                FindingRemediation.target_id == target_id,
            )
        )
        row = existing.scalars().first()
        if row is None:
            return None
        row.verified_in_scan_id = scan_id
        await self._session.flush()
        return self._remediation_dto(row)

    async def list_remediations_for_target(
        self, *, target_id: uuid.UUID
    ) -> dict[str, dict[str, object]]:
        """All remediation workflow rows for one target, keyed by fingerprint.

        Single query backing evidence reports (M5): per-finding workflow
        state plus the M4 verification-rescan link. Caller gates the
        target via a visible scan first.
        """
        from src.infrastructure.database.models import FindingRemediation

        rows = await self._session.execute(
            select(FindingRemediation)
            .where(FindingRemediation.target_id == target_id)
            .order_by(FindingRemediation.fingerprint.asc())
        )
        return {str(row.fingerprint): self._remediation_dto(row) for row in rows.scalars().all()}

    @staticmethod
    def _remediation_dto(row: FindingRemediation) -> dict[str, object]:
        return {
            "id": str(row.id),
            "fingerprint": row.fingerprint,
            "target_id": str(row.target_id),
            "status": row.status,
            "notes": row.notes,
            "updated_by_user_id": str(row.updated_by_user_id)
            if row.updated_by_user_id is not None
            else None,
            "assignee_user_id": str(row.assignee_user_id)
            if row.assignee_user_id is not None
            else None,
            "assigned_at": row.assigned_at.isoformat() if row.assigned_at else None,
            "assigned_by_user_id": str(row.assigned_by_user_id)
            if row.assigned_by_user_id is not None
            else None,
            "due_at": row.due_at.isoformat() if row.due_at else None,
            "verified_in_scan_id": str(row.verified_in_scan_id)
            if row.verified_in_scan_id is not None
            else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

    async def add_comment(
        self, *, fingerprint: str, target_id: uuid.UUID, author_user_id: uuid.UUID, body: str
    ) -> dict[str, object]:
        """Append one collaboration comment (immutable history, never canonical)."""
        from src.infrastructure.database.models import RemediationComment

        row = RemediationComment(
            fingerprint=fingerprint,
            target_id=target_id,
            author_user_id=author_user_id,
            body=body,
        )
        self._session.add(row)
        await self._session.flush()
        return {
            "id": str(row.id),
            "fingerprint": row.fingerprint,
            "target_id": str(row.target_id),
            "author_user_id": str(row.author_user_id),
            "body": row.body,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    async def list_comments(
        self, *, fingerprint: str, target_id: uuid.UUID, limit: int = 100
    ) -> list[dict[str, object]]:
        """Comments for one remediation identity, oldest first (bounded)."""
        from src.infrastructure.database.models import RemediationComment

        rows = await self._session.execute(
            select(RemediationComment)
            .where(
                RemediationComment.fingerprint == fingerprint,
                RemediationComment.target_id == target_id,
            )
            .order_by(RemediationComment.created_at.asc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "fingerprint": row.fingerprint,
                "target_id": str(row.target_id),
                "author_user_id": str(row.author_user_id),
                "body": row.body,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows.scalars().all()
        ]

    async def list_remediations_for_owner_targets(
        self, *, target_ids: list[uuid.UUID]
    ) -> list[dict[str, object]]:
        """Every remediation row across the owner's targets (dashboard input).

        One query for all targets (no N+1); deterministic fingerprint
        order within each target. The caller scopes ``target_ids`` to the
        owner first — this method performs no ownership checks itself.
        """
        from src.infrastructure.database.models import FindingRemediation

        if not target_ids:
            return []
        rows = await self._session.execute(
            select(FindingRemediation)
            .where(FindingRemediation.target_id.in_(target_ids))
            .order_by(FindingRemediation.target_id.asc(), FindingRemediation.fingerprint.asc())
        )
        return [self._remediation_dto(row) for row in rows.scalars().all()]

    @staticmethod
    def _enrichment_dto(row: FindingEnrichment) -> dict[str, object]:
        return {
            "id": str(row.id),
            "fingerprint": row.fingerprint,
            "target_id": str(row.target_id),
            "source": row.source,
            "external_ref": row.external_ref,
            "cve_id": row.cve_id,
            "cwe_id": row.cwe_id,
            "cvss_score": float(row.cvss_score) if row.cvss_score is not None else None,
            "cvss_vector": row.cvss_vector,
            "references": list(row.references or []),
            "affected_technology": row.affected_technology,
            "remediation": row.remediation,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

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
                ScanFinding.fingerprint,
                SeverityLevel.code,
                FindingCategory.code.label("category_code"),
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
                "fingerprint": row.fingerprint,
                "severity": row.code,
                "category": row.category_code,
                "createdAt": row.created_at.isoformat(),
            }
            for row in rows.all()
        ]

    async def list_evidence_for_findings(
        self, finding_ids: list[str]
    ) -> dict[str, list[dict[str, str]]]:
        """Batched evidence rows keyed by finding id (one query per list call).

        Only id/type/content are exposed — evidence rows carry no secrets,
        tokens, or credentials by construction.
        """
        from src.infrastructure.database.models import FindingEvidence

        if not finding_ids:
            return {}
        rows = await self._session.execute(
            select(
                FindingEvidence.finding_id,
                FindingEvidence.id,
                FindingEvidence.evidence_type,
                FindingEvidence.content,
            )
            .where(FindingEvidence.finding_id.in_([uuid.UUID(fid) for fid in finding_ids]))
            .order_by(FindingEvidence.created_at.asc())
        )
        grouped: dict[str, list[dict[str, str]]] = {}
        for row in rows.all():
            grouped.setdefault(str(row.finding_id), []).append(
                {
                    "id": str(row.id),
                    "type": row.evidence_type,
                    "content": row.content,
                }
            )
        return grouped

    async def get_finding_by_id(self, finding_id: uuid.UUID) -> ScanFinding | None:
        """One finding row by id (ownership is verified by the caller)."""
        return await self._session.get(ScanFinding, finding_id)

    async def list_findings_by_fingerprint(
        self, *, fingerprint: str, target_id: uuid.UUID, user_id: uuid.UUID
    ) -> list[dict[str, object]]:
        """Every occurrence of one fingerprint on a target, oldest first.

        Scoped to scans the requester initiated (matches the
        ``_get_visible_scan`` visibility rule, so history never leaks
        another initiator's scans).
        """
        from src.infrastructure.database.models import SeverityLevel

        rows = await self._session.execute(
            select(
                ScanFinding.id,
                ScanFinding.scan_id,
                ScanFinding.title,
                ScanFinding.created_at,
                SeverityLevel.code,
            )
            .join(SeverityLevel, ScanFinding.severity_id == SeverityLevel.id)
            .join(Scan, ScanFinding.scan_id == Scan.id)
            .where(
                ScanFinding.fingerprint == fingerprint,
                ScanFinding.target_id == target_id,
                Scan.initiated_by_user_id == user_id,
            )
            .order_by(ScanFinding.created_at.asc())
        )
        return [
            {
                "id": str(row.id),
                "scan_id": str(row.scan_id),
                "title": row.title,
                "severity": row.code,
                "created_at": row.created_at,
            }
            for row in rows.all()
        ]

    async def lifecycle_events_for_fingerprint(
        self, *, fingerprint: str, target_id: uuid.UUID
    ) -> list[dict[str, object]]:
        """Lifecycle transitions for one fingerprint, oldest first."""
        from src.infrastructure.database.models import (
            FindingLifecycleStatus,
            FindingStatusHistory,
        )

        rows = await self._session.execute(
            select(
                FindingLifecycleStatus.code,
                FindingStatusHistory.effective_at,
                FindingStatusHistory.observed_in_scan_id,
            )
            .join(
                FindingLifecycleStatus,
                FindingStatusHistory.finding_lifecycle_status_id == FindingLifecycleStatus.id,
            )
            .where(
                FindingStatusHistory.fingerprint == fingerprint,
                FindingStatusHistory.target_id == target_id,
            )
            .order_by(FindingStatusHistory.effective_at.asc())
        )
        return [
            {
                "status": row.code,
                "effective_at": row.effective_at,
                "observed_in_scan_id": str(row.observed_in_scan_id),
            }
            for row in rows.all()
        ]

    async def get_finding_with_evidence(self, finding_id: uuid.UUID) -> dict[str, object] | None:
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

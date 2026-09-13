"""Compliance service: owner-scoped evidence gathering + assessment (M9).

Read-only by construction — every method below only SELECTs, and the
pure assessment in :mod:`src.domain.compliance.assessment` cannot
mutate anything. Ownership flows through the existing gates
(visible scans, visible targets, initiator-scoped history), so
cross-owner ids surface as 404, never 403.

Query budget per assessment (STEP 23): targets (1) + completed scans
(1) + finding DTOs (≤25 scans, capped) + lifecycle history (1,
bounded) + remediation maps (1 per target) + enrichment (1 per
target) + technologies (1 per target) + evidence (1). No per-finding
or per-control queries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.domain.compliance.assessment import assess_framework
from src.domain.compliance.catalog import ComplianceFramework, get_framework, list_frameworks
from src.domain.compliance.errors import InvalidComplianceError
from src.domain.errors import NotFoundError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

# Completed-scan states that can anchor finding evidence. Queued /
# running / rejected / cancelled scans carry no persisted findings.
COMPLETED_SCAN_STATUSES = frozenset(
    {
        "SCAN_COMPLETE",
        "AI_ANALYSIS",
        "REPORT_READY",
        "REPORT_READY_DEGRADED",
        "PARTIALLY_COMPLETE",
    }
)

MAX_SCANS_PER_ASSESSMENT = 25


class ComplianceService:
    """Read-only compliance evidence mapping for one owner's data."""

    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._session = session
        self._principal = principal

    # ------------------------------------------------------------------ #
    # Catalog (global, identical for every user — no ownership to scope)  #
    # ------------------------------------------------------------------ #

    async def list_frameworks(self) -> list[dict[str, object]]:
        """Framework catalog entries (id, name, version, source, controls)."""
        return [_framework_entry(framework) for framework in list_frameworks()]

    async def get_framework(self, framework_id: str) -> dict[str, object]:
        """One framework with its controls and mapped categories."""
        framework = _require_framework(framework_id)
        entry = _framework_entry(framework)
        entry["controls"] = [_control_entry(framework, c) for c in framework.controls]
        return entry

    async def list_controls(self, framework_id: str) -> list[dict[str, object]]:
        """Controls of one framework, stable control-id order."""
        framework = _require_framework(framework_id)
        return [
            _control_entry(framework, c)
            for c in sorted(framework.controls, key=lambda c: c.control_id)
        ]

    async def get_control(self, framework_id: str, control_id: str) -> dict[str, object]:
        """One control with its mapped categories and rationale."""
        framework = _require_framework(framework_id)
        for control in framework.controls:
            if control.control_id == control_id:
                return _control_entry(framework, control)
        raise NotFoundError()

    # ------------------------------------------------------------------ #
    # Assessment (owner-scoped evidence)                                   #
    # ------------------------------------------------------------------ #

    async def assess(
        self,
        framework_id: str,
        *,
        scan_id: uuid.UUID | None = None,
        target_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Assess one framework over scan, target, or owner-wide scope.

        Scope resolution is exclusive: scan XOR target, else the whole
        owner account. Foreign scan/target ids are 404 through the
        existing visibility gates. Every control is always present in
        the output (even INSUFFICIENT_EVIDENCE ones) so auditors see
        the full evaluated surface.
        """
        from src.domain.compliance.catalog import MAPPING_VERSION

        framework = _require_framework(framework_id)
        if scan_id is not None and target_id is not None:
            raise InvalidComplianceError("Provide scanId or targetId, not both.")
        findings = await self._finding_views(scan_id=scan_id, target_id=target_id)
        assessment = assess_framework(framework, findings)
        assessment["scope"] = _scope_entry(scan_id=scan_id, target_id=target_id)
        assessment["evaluated_at"] = datetime.now(UTC).isoformat()
        assessment["mapping_version"] = MAPPING_VERSION
        return assessment

    async def _finding_views(
        self,
        *,
        scan_id: uuid.UUID | None,
        target_id: uuid.UUID | None,
    ) -> list[dict[str, Any]]:
        """Finding views for the scope: identifiers + states, batched."""
        from src.domain.scans.scan_service import ScanService
        from src.domain.targets.target_service import TargetService
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )
        from src.infrastructure.database.repositories.target_repository import (
            TargetRepository,
        )

        scan_service = ScanService(self._session, self._principal)
        posture_repo = PostureRepository(self._session)
        executions = ScanEngineExecutionRepository(self._session)

        # (scan_id, target_id, status) triples in scope; the single-scan
        # path resolves through the visibility gate (foreign ids 404).
        triples: list[tuple[uuid.UUID, uuid.UUID, str]] = []
        if scan_id is not None:
            scan = await scan_service._get_visible_scan(scan_id)
            triples.append((scan.id, scan.target_id, await self._status_of_scan(scan)))
        else:
            if target_id is not None:
                target = await TargetService(self._session, self._principal).get_target(target_id)
                target_uuids = [target.id]
            else:
                targets = await posture_repo.list_owned_targets(self._principal.id)
                target_uuids = _uuid_list(targets)
            for row in await self._completed_scans(scan_service, target_id=target_id):
                triples.append((row.id, row.target_id, row.status_code))
        triples = [t for t in triples if t[2] in COMPLETED_SCAN_STATUSES]
        triples.sort(key=lambda t: str(t[0]))
        triples = triples[:MAX_SCANS_PER_ASSESSMENT]
        target_uuids = sorted({t[1] for t in triples}, key=str)
        if not triples:
            return []

        # Finding DTOs across the capped scan set (one query per scan),
        # first occurrence wins so rescans never double-count identities.
        dtos: list[dict[str, Any]] = []
        scan_of_finding: dict[str, uuid.UUID] = {}
        target_of_scan: dict[str, uuid.UUID] = {}
        for row_scan_id, row_target_id, _status in triples:
            target_of_scan[str(row_scan_id)] = row_target_id
            for dto in await executions.list_finding_dtos(row_scan_id):
                key = str(dto.get("id", ""))
                if key and key not in scan_of_finding:
                    scan_of_finding[key] = row_scan_id
                    dtos.append(dict(dto))
        if not dtos:
            return []

        finding_ids = [str(d.get("id", "")) for d in dtos if d.get("id")]
        evidence_by_finding = await executions.list_evidence_for_findings(finding_ids)

        # Latest lifecycle per (target, fingerprint), one bounded query.
        history = await posture_repo.history_events(target_uuids, limit=10_000)
        latest_lifecycle: dict[tuple[str, str], str] = {}
        for event in history:
            event_target = event.get("target_id")
            event_fp = event.get("fingerprint")
            event_status = event.get("status")
            if (
                isinstance(event_target, str)
                and isinstance(event_fp, str)
                and event_status is not None
            ):
                latest_lifecycle[(event_target, event_fp)] = str(event_status)

        # Remediation + enrichment + technologies, batched per target.
        remediation_by_fp: dict[str, dict[str, object]] = {}
        enrichment_by_fp: dict[str, list[dict[str, object]]] = {}
        technologies_by_target: dict[str, tuple[str, ...]] = {}
        for target_uuid in target_uuids:
            for fingerprint, row in (
                await executions.list_remediations_for_target(target_id=target_uuid)
            ).items():
                remediation_by_fp.setdefault(f"{target_uuid}|{fingerprint}", row)
            fingerprints = sorted(
                {str(d.get("fingerprint", "")) for d in dtos if d.get("fingerprint")}
            )
            for fingerprint, rows in (
                await executions.list_enrichment_for_fingerprints(
                    fingerprints=fingerprints, target_id=target_uuid
                )
            ).items():
                enrichment_by_fp.setdefault(f"{target_uuid}|{fingerprint}", rows)
            technologies_by_target[str(target_uuid)] = tuple(
                sorted(
                    {
                        str(t.get("slug", ""))
                        for t in await TargetRepository(self._session).list_technologies(
                            target_uuid
                        )
                        if t.get("slug")
                    }
                )
            )

        views: list[dict[str, Any]] = []
        for dto in dtos:
            finding_scan_id = scan_of_finding.get(str(dto.get("id", "")))
            view_target: uuid.UUID | None = None
            if finding_scan_id is not None:
                view_target = target_of_scan.get(str(finding_scan_id))
            if view_target is None:
                continue
            fingerprint = str(dto.get("fingerprint", "") or "")
            lifecycle = latest_lifecycle.get((str(view_target), fingerprint))
            remediation = remediation_by_fp.get(f"{view_target}|{fingerprint}", {})
            enrichment = enrichment_by_fp.get(f"{view_target}|{fingerprint}", [])
            technologies = technologies_by_target.get(str(view_target), ())
            views.append(
                {
                    "finding_id": str(dto.get("id", "")),
                    "fingerprint": fingerprint,
                    "target_id": str(view_target),
                    "scan_id": str(scan_of_finding.get(str(dto.get("id", "")), "")),
                    "category": dto.get("category"),
                    "title": str(dto.get("title", "")),
                    "severity": str(dto.get("severity", "") or ""),
                    "lifecycle": lifecycle,
                    "remediation_status": remediation.get("status"),
                    "priority_level": _priority_level(
                        severity=str(dto.get("severity", "") or ""),
                        lifecycle=lifecycle,
                        enrichment=enrichment,
                        technologies=technologies,
                    ),
                    "evidence": [
                        {"id": str(item.get("id", "")), "type": str(item.get("type", ""))}
                        for item in evidence_by_finding.get(str(dto.get("id", "")), [])
                    ],
                    "observed_at": dto.get("createdAt"),
                }
            )
        views.sort(
            key=lambda v: (
                str(v.get("target_id", "")),
                str(v.get("fingerprint", "")),
                str(v.get("scan_id", "")),
            )
        )
        return views

    async def _completed_scans(
        self, scan_service: Any, *, target_id: uuid.UUID | None
    ) -> list[Any]:
        """Completed scans in scope, newest first (bounded for assessment)."""
        rows = await scan_service.list_scans(target_id=target_id, limit=MAX_SCANS_PER_ASSESSMENT)
        return [row for row in rows if row.status_code in COMPLETED_SCAN_STATUSES]

    async def _status_of_scan(self, scan: Any) -> str:
        """Canonical status code for one scan row."""
        status_code = getattr(scan, "status_code", None)
        if isinstance(status_code, str):
            return status_code
        from src.infrastructure.database.repositories.scan_repository import (
            _status_code_of,
        )

        return await _status_code_of(self._session, scan.status_id)


def _priority_level(
    *,
    severity: str,
    lifecycle: str | None,
    enrichment: list[dict[str, object]],
    technologies: tuple[str, ...],
) -> str | None:
    """Point-in-time priority level for triage (documented snapshot).

    Same v2 calculator the posture views use, with the signals
    available in batch (severity, lifecycle, CVE/CVSS enrichment,
    technologies). ``previous_severity`` is unavailable without a
    per-finding history query (N+1), so it stays None here — the
    canonical priority lives in posture/reports; this level only
    orders compliance attention.
    """
    if not severity:
        return None
    from src.domain.posture.posture_service import _priority_snapshot

    try:
        snapshot = _priority_snapshot(
            severity=severity,
            lifecycle_status=lifecycle,
            previous_severity=None,
            enrichment_rows=enrichment,
            technologies=technologies,
        )
    except Exception:
        return None
    level = snapshot.get("level")
    return str(level) if isinstance(level, str) else None


def _require_framework(framework_id: str) -> ComplianceFramework:
    framework = get_framework(framework_id)
    if framework is None:
        raise NotFoundError()
    return framework


def _framework_entry(framework: ComplianceFramework) -> dict[str, object]:
    from src.domain.compliance.catalog import MAPPING_VERSION

    return {
        "framework_id": framework.framework_id,
        "name": framework.name,
        "version": framework.version,
        "source": framework.source,
        "mapping_version": MAPPING_VERSION,
        "control_count": len(framework.controls),
    }


def _control_entry(framework: ComplianceFramework, control: Any) -> dict[str, object]:
    categories = sorted(
        category
        for category, control_ids in framework.mappings.items()
        if control.control_id in control_ids
    )
    return {
        "framework_id": framework.framework_id,
        "control_id": control.control_id,
        "title": control.title,
        "description": control.description,
        "rationale": framework.rationales.get(control.control_id, ""),
        "mapped_categories": categories,
    }


def _scope_entry(*, scan_id: uuid.UUID | None, target_id: uuid.UUID | None) -> dict[str, object]:
    if scan_id is not None:
        return {"type": "scan", "scan_id": str(scan_id)}
    if target_id is not None:
        return {"type": "target", "target_id": str(target_id)}
    return {"type": "owner"}


def _uuid_list(targets: list[dict[str, object]]) -> list[uuid.UUID]:
    out: list[uuid.UUID] = []
    for target in targets:
        raw = target.get("id")
        if isinstance(raw, str) and raw:
            try:
                out.append(uuid.UUID(raw))
            except ValueError:
                continue
    return out

"""Bounded investigation evidence (M12, deterministic, read-only).

``build_evidence`` assembles the minimum data the narrator needs from
systems M5–M9 — findings, lifecycle, remediation, enrichment/CVE,
technologies, compliance statuses, posture delta — behind the existing
owner gates. Hard caps bound every dimension; anything cut is counted
in ``omitted`` so the AI (and the reader) knows the view is partial.
Finding titles and evidence travel as data with stable IDs; the
validator later checks every AI citation against the registries built
here. No raw evidence bodies are included — only evidence id/type
references.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

MAX_FINDINGS = 25
MAX_FIELD_CHARS = 500
MAX_EVIDENCE_REFS_PER_FINDING = 10
MAX_CVES = 20
MAX_TECHNOLOGIES = 20
MAX_SCANS_HISTORY = 5
MAX_PROMPT_CHARS = 60_000


@dataclass(frozen=True)
class InvestigationEvidence:
    """Bounded evidence view + citation registries for one target scope."""

    target_id: str
    scan_id: str | None
    scan_status: str | None
    generated_at: str
    findings: tuple[dict[str, Any], ...] = ()
    omitted_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    lifecycle_counts: dict[str, int] = field(default_factory=dict)
    remediation_counts: dict[str, int] = field(default_factory=dict)
    cves: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    compliance: tuple[dict[str, Any], ...] = ()
    posture_delta: dict[str, Any] = field(default_factory=dict)
    scan_history: tuple[dict[str, Any], ...] = ()
    # Citation registries (validator allow-lists).
    finding_ids: frozenset[str] = frozenset()
    evidence_ids: frozenset[str] = frozenset()
    control_ids: frozenset[str] = frozenset()
    cve_set: frozenset[str] = frozenset()

    def summary(self) -> dict[str, Any]:
        """Deterministic counts for responses and fallbacks (no AI needed)."""
        return {
            "target_id": self.target_id,
            "scan_id": self.scan_id,
            "scan_status": self.scan_status,
            "finding_count": len(self.findings),
            "omitted_findings": self.omitted_findings,
            "severity_counts": dict(self.severity_counts),
            "lifecycle_counts": dict(self.lifecycle_counts),
            "remediation_counts": dict(self.remediation_counts),
            "cves": list(self.cves),
            "technologies": list(self.technologies),
            "posture_delta": dict(self.posture_delta),
        }


async def build_evidence(
    session: AsyncSession,
    principal: UserAccount,
    *,
    target_id: uuid.UUID,
    scan_id: uuid.UUID | None = None,
) -> InvestigationEvidence:
    """Assemble the bounded view (owner gates inside; foreign ids 404)."""
    from src.domain.scans.scan_service import REPORT_V2_COMPLETED_STATUSES, ScanService
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

    target = await TargetService(session, principal).get_target(target_id)
    scan_service = ScanService(session, principal)
    posture_repo = PostureRepository(session)
    executions = ScanEngineExecutionRepository(session)

    scans = await scan_service.list_scans(target_id=target.id, limit=50)
    completed = [s for s in scans if s.status_code in REPORT_V2_COMPLETED_STATUSES]
    focus: Any = None
    if scan_id is not None:
        scan = await scan_service._get_visible_scan(scan_id)
        if scan.target_id != target.id:
            from src.domain.errors import NotFoundError

            raise NotFoundError()
        focus = scan
    elif completed:
        focus = max(completed, key=lambda s: s.created_at)

    history = await posture_repo.history_events([target.id], limit=10_000)
    latest_lifecycle: dict[str, str] = {}
    for event in history:
        fingerprint = event.get("fingerprint")
        status = event.get("status")
        if isinstance(fingerprint, str) and status is not None:
            latest_lifecycle[fingerprint] = str(status)

    remediation_map = await executions.list_remediations_for_target(target_id=target.id)
    technologies = await TargetRepository(session).list_technologies(target.id)
    tech_slugs = tuple(
        sorted({str(t.get("slug", "")) for t in technologies if t.get("slug")})[:MAX_TECHNOLOGIES]
    )

    dtos: list[dict[str, Any]] = []
    evidence_by_finding: dict[str, list[dict[str, str]]] = {}
    if focus is not None:
        dtos = [dict(d) for d in await executions.list_finding_dtos(focus.id)]
        evidence_by_finding = await executions.list_evidence_for_findings(
            [str(d.get("id", "")) for d in dtos if d.get("id")]
        )

    fingerprints = sorted(
        {str(d.get("fingerprint", "") or "") for d in dtos if d.get("fingerprint")}
    )
    enrichment = await executions.list_enrichment_for_fingerprints(
        fingerprints=fingerprints, target_id=target.id
    )

    findings: list[dict[str, Any]] = []
    cve_set: set[str] = set()
    evidence_ids: set[str] = set()
    for dto in dtos:
        fingerprint = str(dto.get("fingerprint", "") or "")
        rows = enrichment.get(fingerprint, [])
        for row in rows:
            cve = row.get("cve_id")
            if isinstance(cve, str) and cve:
                cve_set.add(cve)
        refs = [
            {"id": str(item.get("id", "")), "type": str(item.get("type", ""))}
            for item in evidence_by_finding.get(str(dto.get("id", "")), [])[
                :MAX_EVIDENCE_REFS_PER_FINDING
            ]
        ]
        for ref in refs:
            evidence_ids.add(ref["id"])
        findings.append(
            {
                "finding_id": str(dto.get("id", "")),
                "fingerprint": fingerprint,
                "title": _clip(str(dto.get("title", ""))),
                "severity": str(dto.get("severity", "") or ""),
                "category": str(dto.get("category", "") or ""),
                "lifecycle": latest_lifecycle.get(fingerprint),
                "remediation_status": _remediation_status(remediation_map.get(fingerprint)),
                "priority_level": _priority_level(
                    severity=str(dto.get("severity", "") or ""),
                    lifecycle=latest_lifecycle.get(fingerprint),
                    enrichment=enrichment.get(fingerprint, []),
                    technologies=tech_slugs,
                ),
                "cves": sorted({str(r.get("cve_id", "")) for r in rows if r.get("cve_id")})[
                    :MAX_CVES
                ],
                "evidence": refs,
            }
        )
    findings.sort(key=lambda f: (str(f["severity"]), str(f["fingerprint"])))
    omitted = max(0, len(findings) - MAX_FINDINGS)
    findings = findings[:MAX_FINDINGS]

    compliance = await _compliance_statuses(session, principal, target.id)
    control_ids = frozenset(
        c["control_id"] for framework in compliance for c in framework["controls"]
    )
    return InvestigationEvidence(
        target_id=str(target.id),
        scan_id=str(focus.id) if focus is not None else None,
        scan_status=await _scan_status(session, focus),
        generated_at=datetime.now(UTC).isoformat(),
        findings=tuple(findings),
        omitted_findings=omitted,
        severity_counts=_tally(findings, "severity"),
        lifecycle_counts=_tally(findings, "lifecycle", unknown="UNKNOWN"),
        remediation_counts=_tally(findings, "remediation_status", unknown="UNTRACKED"),
        cves=tuple(sorted(cve_set)[:MAX_CVES]),
        technologies=tech_slugs,
        compliance=tuple(compliance),
        posture_delta=await _posture_delta(scan_service, completed),
        scan_history=tuple(
            {
                "scan_id": str(s.id),
                "status": s.status_code,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in sorted(completed, key=lambda s: s.created_at, reverse=True)[:MAX_SCANS_HISTORY]
        ),
        finding_ids=frozenset(str(f["finding_id"]) for f in findings),
        evidence_ids=frozenset(evidence_ids),
        control_ids=control_ids,
        cve_set=frozenset(cve_set),
    )


def _clip(text: str, limit: int = MAX_FIELD_CHARS) -> str:
    clipped = text[:limit]
    return clipped + "… [truncated]" if len(text) > limit else clipped


def _tally(
    findings: list[dict[str, Any]], key: str, *, unknown: str | None = None
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        raw = finding.get(key)
        label = str(raw) if isinstance(raw, str) and raw else unknown
        if label is None:
            continue
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _remediation_status(row: dict[str, object] | None) -> str | None:
    if row is None:
        return None
    status = row.get("status")
    return str(status) if isinstance(status, str) else None


def _priority_level(
    *,
    severity: str,
    lifecycle: str | None,
    enrichment: list[dict[str, object]],
    technologies: tuple[str, ...],
) -> str | None:
    """Point-in-time triage level (same documented snapshot as compliance)."""
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


async def _scan_status(session: AsyncSession, focus: Any) -> str | None:
    if focus is None:
        return None
    status_code = getattr(focus, "status_code", None)
    if isinstance(status_code, str):
        return status_code
    from src.infrastructure.database.repositories.scan_repository import (
        _status_code_of,
    )

    return await _status_code_of(session, focus.status_id)


async def _compliance_statuses(
    session: AsyncSession, principal: UserAccount, target_id: uuid.UUID
) -> list[dict[str, Any]]:
    """Per-framework control statuses (small curated surface, reused service)."""
    from src.domain.compliance.service import ComplianceService

    out: list[dict[str, Any]] = []
    service = ComplianceService(session, principal)
    for framework_id in ("pci-dss", "iso-27001", "soc-2"):
        assessment = await service.assess(framework_id, target_id=target_id)
        out.append(
            {
                "framework": framework_id,
                "controls": [
                    {"control_id": c["control_id"], "status": c["status"]}
                    for c in assessment["controls"]
                ],
            }
        )
    return out


async def _posture_delta(scan_service: Any, completed: list[Any]) -> dict[str, Any]:
    """New/resolved/regressed counts between the two latest completed scans."""
    if len(completed) < 2:
        return {"comparable": False}
    ordered = sorted(completed, key=lambda s: s.created_at)
    try:
        buckets = await scan_service.compare_scans(ordered[-2].id, ordered[-1].id)
    except Exception:
        return {"comparable": False}
    return {
        "comparable": True,
        "previous_scan_id": str(ordered[-2].id),
        "current_scan_id": str(ordered[-1].id),
        "new": len(buckets.get("new", [])),
        "resolved": len(buckets.get("resolved", [])),
        "regressed": len(buckets.get("regressed", [])),
        "persistent": len(buckets.get("persistent", [])),
    }


__all__ = [
    "MAX_CVES",
    "MAX_EVIDENCE_REFS_PER_FINDING",
    "MAX_FIELD_CHARS",
    "MAX_FINDINGS",
    "MAX_PROMPT_CHARS",
    "MAX_SCANS_HISTORY",
    "MAX_TECHNOLOGIES",
    "InvestigationEvidence",
    "build_evidence",
]

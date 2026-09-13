"""Posture repository: batched read aggregates for the dashboard layer.

Every method is scoped to one owner's data and batched across that
owner's targets/scans — the dashboard must never issue one query per
target or per finding. All methods return plain dicts/lists (no ORM
rows leak past this boundary); time-series callers cap scan counts.

PostgreSQL idioms used here (DISTINCT ON, JSONB-free grouping) match the
rest of the persistence layer, which already assumes PostgreSQL.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from src.infrastructure.database.models import (
    FindingEnrichment,
    FindingLifecycleStatus,
    FindingStatusHistory,
    Scan,
    ScanFinding,
    ScanStatus,
    SeverityLevel,
    Target,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


class PostureRepository:
    """Batched aggregate reads backing security-posture endpoints."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_owned_targets(self, user_id: uuid.UUID) -> list[dict[str, object]]:
        """All targets owned by the user, oldest first (stable order)."""
        rows = await self._session.execute(
            select(Target).where(Target.owner_user_id == user_id).order_by(Target.created_at.asc())
        )
        return [
            {
                "id": str(row.id),
                "hostname": row.hostname,
                "normalized_url": row.normalized_url,
                "is_archived": bool(row.is_archived),
                "created_at": row.created_at,
            }
            for row in rows.scalars().all()
        ]

    async def list_scans_for_user(
        self, user_id: uuid.UUID, *, limit: int
    ) -> list[dict[str, object]]:
        """User's scans newest-first with status codes (bounded by limit)."""
        rows = await self._session.execute(
            select(Scan, ScanStatus.code)
            .join(ScanStatus, Scan.status_id == ScanStatus.id)
            .where(Scan.initiated_by_user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        return [
            {
                "id": str(scan.id),
                "target_id": str(scan.target_id),
                "status": str(status_code),
                "parent_scan_id": str(scan.parent_scan_id) if scan.parent_scan_id else None,
                "completed_at": scan.completed_at,
                "created_at": scan.created_at,
            }
            for scan, status_code in rows.all()
        ]

    async def count_scans_for_user(self, user_id: uuid.UUID) -> dict[str, int]:
        """Exact scan totals for one owner (no cross-user aggregates)."""
        total = await self._session.execute(
            select(func.count(Scan.id)).where(Scan.initiated_by_user_id == user_id)
        )
        completed = await self._session.execute(
            select(func.count(Scan.id))
            .join(ScanStatus, Scan.status_id == ScanStatus.id)
            .where(
                Scan.initiated_by_user_id == user_id,
                Scan.completed_at.is_not(None),
            )
        )
        return {"total": int(total.scalar() or 0), "completed": int(completed.scalar() or 0)}

    async def latest_lifecycle_map(
        self, target_ids: list[uuid.UUID]
    ) -> dict[tuple[str, str], dict[str, object]]:
        """Latest lifecycle status per (target, fingerprint).

        Uses DISTINCT ON so each identity contributes exactly one row:
        the freshest ``effective_at`` entry.
        """
        if not target_ids:
            return {}
        subquery = (
            select(
                FindingStatusHistory.target_id,
                FindingStatusHistory.fingerprint,
                FindingStatusHistory.finding_lifecycle_status_id,
                FindingStatusHistory.effective_at,
                FindingStatusHistory.observed_in_scan_id,
            )
            .where(FindingStatusHistory.target_id.in_(target_ids))
            .distinct(FindingStatusHistory.target_id, FindingStatusHistory.fingerprint)
            .order_by(
                FindingStatusHistory.target_id,
                FindingStatusHistory.fingerprint,
                FindingStatusHistory.effective_at.desc(),
            )
            .subquery()
        )
        rows = await self._session.execute(
            select(
                subquery.c.target_id,
                subquery.c.fingerprint,
                FindingLifecycleStatus.code,
                subquery.c.effective_at,
                subquery.c.observed_in_scan_id,
            ).join(
                FindingLifecycleStatus,
                FindingLifecycleStatus.id == subquery.c.finding_lifecycle_status_id,
            )
        )
        return {
            (str(target_id), str(fingerprint)): {
                "status": str(code),
                "effective_at": effective_at,
                "observed_in_scan_id": str(observed_in_scan_id),
            }
            for target_id, fingerprint, code, effective_at, observed_in_scan_id in rows.all()
        }

    async def latest_findings_map(
        self, user_id: uuid.UUID, target_ids: list[uuid.UUID]
    ) -> dict[tuple[str, str], dict[str, object]]:
        """Newest finding row per (target, fingerprint) for the owner's scans."""
        if not target_ids:
            return {}
        subquery = (
            select(
                ScanFinding.target_id,
                ScanFinding.fingerprint,
                ScanFinding.id,
                ScanFinding.scan_id,
                ScanFinding.title,
                ScanFinding.severity_id,
                ScanFinding.created_at,
            )
            .join(Scan, ScanFinding.scan_id == Scan.id)
            .where(
                ScanFinding.target_id.in_(target_ids),
                ScanFinding.fingerprint.is_not(None),
                Scan.initiated_by_user_id == user_id,
            )
            .distinct(ScanFinding.target_id, ScanFinding.fingerprint)
            .order_by(
                ScanFinding.target_id,
                ScanFinding.fingerprint,
                ScanFinding.created_at.desc(),
            )
            .subquery()
        )
        rows = await self._session.execute(
            select(
                subquery.c.target_id,
                subquery.c.fingerprint,
                subquery.c.id,
                subquery.c.scan_id,
                subquery.c.title,
                SeverityLevel.code,
                subquery.c.created_at,
            ).join(SeverityLevel, SeverityLevel.id == subquery.c.severity_id)
        )
        return {
            (str(target_id), str(fingerprint)): {
                "finding_id": str(finding_id),
                "scan_id": str(scan_id),
                "title": str(title),
                "severity": str(severity_code),
                "created_at": created_at,
            }
            for target_id, fingerprint, finding_id, scan_id, title, severity_code, created_at in rows.all()
        }

    async def findings_by_scan(
        self, user_id: uuid.UUID, scan_ids: list[uuid.UUID]
    ) -> dict[str, list[dict[str, object]]]:
        """Fingerprinted findings grouped by scan (trend/lifecycle input).

        One query for all requested scans; rows without fingerprints are
        excluded (they carry no cross-scan identity).
        """
        if not scan_ids:
            return {}
        rows = await self._session.execute(
            select(
                ScanFinding.scan_id,
                ScanFinding.id,
                ScanFinding.fingerprint,
                ScanFinding.title,
                SeverityLevel.code,
                ScanFinding.created_at,
            )
            .join(SeverityLevel, ScanFinding.severity_id == SeverityLevel.id)
            .join(Scan, ScanFinding.scan_id == Scan.id)
            .where(
                ScanFinding.scan_id.in_(scan_ids),
                ScanFinding.fingerprint.is_not(None),
                Scan.initiated_by_user_id == user_id,
            )
            .order_by(ScanFinding.created_at.asc())
        )
        grouped: dict[str, list[dict[str, object]]] = {}
        for scan_id, finding_id, fingerprint, title, severity_code, created_at in rows.all():
            grouped.setdefault(str(scan_id), []).append(
                {
                    "finding_id": str(finding_id),
                    "fingerprint": str(fingerprint),
                    "title": str(title),
                    "severity": str(severity_code),
                    "created_at": created_at,
                }
            )
        return grouped

    async def history_events(
        self, target_ids: list[uuid.UUID], *, limit: int = 10_000
    ) -> list[dict[str, object]]:
        """Lifecycle events for the owner's targets, chronologically.

        Bounded (default 10k rows) so MTTR computation stays practical;
        the bound is documented on the response when hit is detectable by
        callers via row counts they already hold. Sorted for determinism.
        """
        if not target_ids:
            return []
        rows = await self._session.execute(
            select(
                FindingStatusHistory.target_id,
                FindingStatusHistory.fingerprint,
                FindingLifecycleStatus.code,
                FindingStatusHistory.effective_at,
                FindingStatusHistory.observed_in_scan_id,
            )
            .join(
                FindingLifecycleStatus,
                FindingLifecycleStatus.id == FindingStatusHistory.finding_lifecycle_status_id,
            )
            .where(FindingStatusHistory.target_id.in_(target_ids))
            .order_by(
                FindingStatusHistory.target_id,
                FindingStatusHistory.fingerprint,
                FindingStatusHistory.effective_at.asc(),
            )
            .limit(limit)
        )
        return [
            {
                "target_id": str(target_id),
                "fingerprint": str(fingerprint),
                "status": str(code),
                "effective_at": effective_at,
                "observed_in_scan_id": str(observed_in_scan_id),
            }
            for target_id, fingerprint, code, effective_at, observed_in_scan_id in rows.all()
        ]

    async def remediation_map(
        self, target_ids: list[uuid.UUID]
    ) -> dict[tuple[str, str], dict[str, object]]:
        """Remediation workflow rows keyed by (target, fingerprint)."""
        if not target_ids:
            return {}
        from src.infrastructure.database.models import FindingRemediation

        rows = await self._session.execute(
            select(FindingRemediation).where(FindingRemediation.target_id.in_(target_ids))
        )
        return {
            (str(row.target_id), str(row.fingerprint)): {
                "status": str(row.status),
                "updated_at": row.updated_at,
            }
            for row in rows.scalars().all()
        }

    async def technologies_map(
        self, target_ids: list[uuid.UUID]
    ) -> dict[str, list[dict[str, object]]]:
        """Technology inventory grouped by target (one query for all)."""
        if not target_ids:
            return {}
        from src.infrastructure.database.models import TargetTechnology

        rows = await self._session.execute(
            select(TargetTechnology)
            .where(TargetTechnology.target_id.in_(target_ids))
            .order_by(TargetTechnology.slug.asc())
        )
        grouped: dict[str, list[dict[str, object]]] = {}
        for row in rows.scalars().all():
            grouped.setdefault(str(row.target_id), []).append(
                {
                    "slug": str(row.slug),
                    "display": str(row.display),
                    "family": str(row.family),
                    "version": row.version,
                    "confidence": str(row.confidence),
                    "first_observed_at": row.first_observed_at,
                    "last_observed_at": row.last_observed_at,
                }
            )
        return grouped

    async def lifecycle_at_scan(self, target_id: uuid.UUID, scan_id: uuid.UUID) -> dict[str, str]:
        """Latest lifecycle status per fingerprint observed in one scan."""
        rows = await self._session.execute(
            select(
                FindingStatusHistory.fingerprint,
                FindingLifecycleStatus.code,
                FindingStatusHistory.effective_at,
            )
            .join(
                FindingLifecycleStatus,
                FindingLifecycleStatus.id == FindingStatusHistory.finding_lifecycle_status_id,
            )
            .where(
                FindingStatusHistory.target_id == target_id,
                FindingStatusHistory.observed_in_scan_id == scan_id,
            )
            .order_by(FindingStatusHistory.effective_at.desc())
        )
        out: dict[str, str] = {}
        for fingerprint, code, _at in rows.all():
            out.setdefault(str(fingerprint), str(code))
        return out

    async def enrichment_map(
        self, target_ids: list[uuid.UUID]
    ) -> dict[tuple[str, str], list[dict[str, object]]]:
        """Enrichment rows grouped by (target, fingerprint), oldest first."""
        if not target_ids:
            return {}
        rows = await self._session.execute(
            select(FindingEnrichment)
            .where(FindingEnrichment.target_id.in_(target_ids))
            .order_by(FindingEnrichment.created_at.asc())
        )
        grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
        for row in rows.scalars().all():
            grouped.setdefault((str(row.target_id), str(row.fingerprint)), []).append(
                {
                    "source": row.source,
                    "external_ref": row.external_ref,
                    "cve_id": row.cve_id,
                    "cwe_id": row.cwe_id,
                    "cvss_score": float(row.cvss_score) if row.cvss_score is not None else None,
                    "affected_technology": row.affected_technology,
                    "created_at": row.created_at,
                }
            )
        return grouped

    async def lifecycle_for_scans(self, scan_ids: list[uuid.UUID]) -> dict[str, dict[str, str]]:
        """Latest lifecycle status per fingerprint for each scan.

        One query for the whole set: statuses observed in the scan,
        freshest first per (scan, fingerprint).
        """
        if not scan_ids:
            return {}
        rows = await self._session.execute(
            select(
                FindingStatusHistory.observed_in_scan_id,
                FindingStatusHistory.fingerprint,
                FindingLifecycleStatus.code,
                FindingStatusHistory.effective_at,
            )
            .join(
                FindingLifecycleStatus,
                FindingLifecycleStatus.id == FindingStatusHistory.finding_lifecycle_status_id,
            )
            .where(FindingStatusHistory.observed_in_scan_id.in_(scan_ids))
            .order_by(FindingStatusHistory.effective_at.desc())
        )
        out: dict[str, dict[str, str]] = {}
        for scan_id, fingerprint, code, _at in rows.all():
            out.setdefault(str(scan_id), {}).setdefault(str(fingerprint), str(code))
        return out

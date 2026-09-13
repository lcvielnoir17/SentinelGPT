"""Security posture service: deterministic read models over canonical data.

Posture is DERIVED, never stored: every metric recomputes from targets,
scans, findings, lifecycle history, remediation, enrichment, and
technology rows. Definitions:

* **Open finding** — a (target, fingerprint) identity whose latest
  lifecycle status is NEW, PERSISTENT, or REGRESSED. Identities without
  any fingerprinted finding row (pre-identity history) are skipped and
  counted as ``unresolved_identities`` rather than guessed at.
* **Priority** — Priority v2 computed with the same inputs as reports
  and comparison (severity, lifecycle, previous severity where the
  caller holds it, CVE/CVSS enrichment, paired technology). One shared
  helper, no dashboard-specific scoring.
* **Remediation vs lifecycle** — workflow DONE never implies lifecycle
  RESOLVED; ``done_open`` items surface exactly that gap.
* **MTTR** — per (target, fingerprint): first NEW event to the first
  later RESOLVED event, in hours. Identities never resolved are
  excluded from the sample (counted separately); no sample means
  ``mttr: null``, never a fabricated zero.
* **Trends** — per completed scan, oldest first: severity counts, v2
  priority counts (full era-appropriate inputs), and new/resolved/
  regressed deltas against the previous completed scan of the same
  target. Remediation has no per-scan history, so it appears only in
  current snapshots — never as a backfilled series.

Ownership: every query filters to the principal's targets/scans. Empty
accounts receive honest zeros/empties (200), never 404.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import mean, median
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import uuid
    from collections.abc import Iterable

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

from src.domain.scans.priority import (
    PRIORITY_VERSION_V2,
    PriorityInputsV2,
    calculate_priority_v2,
    match_technologies,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

OPEN_STATUSES = ("NEW", "PERSISTENT", "REGRESSED")

_SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

_TOP_FINDINGS_LIMIT = 20
_TOP_REGRESSIONS_LIMIT = 10
_DONE_OPEN_LIMIT = 20
_SCANS_LIST_LIMIT = 1000
_DEFAULT_TREND_LIMIT = 20
_MAX_TREND_LIMIT = 50
_DEFAULT_TARGETS_LIMIT = 50
_MAX_TARGETS_LIMIT = 200


def _as_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def _iso(moment: datetime | None) -> str | None:
    return _as_aware(moment).isoformat() if moment is not None else None


def _priority_snapshot(
    *,
    severity: str,
    lifecycle_status: str | None,
    previous_severity: str | None,
    enrichment_rows: list[dict[str, object]],
    technologies: tuple[str, ...] = (),
) -> dict[str, object]:
    """v2 snapshot shared by posture, trends, and target views."""
    has_cve = any(row.get("cve_id") for row in enrichment_rows)
    scores = [
        float(score)
        for row in enrichment_rows
        if isinstance((score := row.get("cvss_score")), (int, float))
    ]
    matched = match_technologies(technologies, enrichment_rows)
    result = calculate_priority_v2(
        PriorityInputsV2(
            severity=severity,
            lifecycle_status=lifecycle_status,
            previous_severity=previous_severity,
            has_cve=has_cve,
            cvss_score=max(scores) if scores else None,
            technologies=technologies,
            matched_technologies=matched,
        )
    )
    return {
        "score": result.score,
        "level": result.level,
        "version": result.version,
        "factors": list(result.factors),
    }


def _enrichment_at(
    rows: list[dict[str, object]], as_of: datetime | None
) -> list[dict[str, object]]:
    """Enrichment rows present at a moment (all rows when ``as_of`` is None)."""
    if as_of is None:
        return list(rows)
    present: list[dict[str, object]] = []
    for row in rows:
        created = row.get("created_at")
        if not isinstance(created, datetime):
            continue
        if _as_aware(created) <= _as_aware(as_of):
            present.append(row)
    return present


def _technologies_at(rows: list[dict[str, object]], as_of: datetime | None) -> tuple[str, ...]:
    """Technology slugs first observed at or before a moment."""
    if as_of is None:
        return tuple(sorted({str(r["slug"]) for r in rows if r.get("slug")}))
    present: set[str] = set()
    for row in rows:
        if not row.get("slug"):
            continue
        first = row.get("first_observed_at")
        if not isinstance(first, datetime):
            continue
        if _as_aware(first) <= _as_aware(as_of):
            present.add(str(row["slug"]))
    return tuple(sorted(present))


@dataclass(frozen=True)
class _OpenFinding:
    """One open identity with everything needed to score and rank it."""

    target_id: str
    hostname: str
    fingerprint: str
    finding_id: str
    scan_id: str
    title: str
    severity: str
    lifecycle_status: str
    previous_severity: str | None
    priority: dict[str, object]
    remediation_status: str | None


class PostureService:
    """Deterministic posture read models for one owner's data."""

    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._session = session
        self._principal = principal

    # ------------------------------------------------------------------ #
    # Public endpoints                                                    #
    # ------------------------------------------------------------------ #

    async def get_posture(self) -> dict[str, object]:
        """Current security-posture snapshot for the principal."""
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )

        user_id = self._principal.id
        repository = PostureRepository(self._session)
        targets = await repository.list_owned_targets(user_id)
        target_ids = [t["id"] for t in targets]
        hostnames = {str(t["id"]): str(t["hostname"]) for t in targets}
        scans = await repository.list_scans_for_user(user_id, limit=_SCANS_LIST_LIMIT)
        counts = await repository.count_scans_for_user(user_id)

        open_findings, unresolved_identities = await self._open_findings(target_ids, hostnames)
        remediation = await repository.remediation_map(_uuids(target_ids))
        remediation_counts = _tally(str(r["status"]) for r in remediation.values())
        done_open = [
            {
                "target_id": finding.target_id,
                "hostname": finding.hostname,
                "fingerprint": finding.fingerprint,
                "severity": finding.severity,
                "priority": finding.priority,
            }
            for finding in open_findings
            if finding.remediation_status == "DONE"
        ][:_DONE_OPEN_LIMIT]
        done_open_count = sum(
            1 for finding in open_findings if finding.remediation_status == "DONE"
        )

        regressions = [f for f in open_findings if f.lifecycle_status == "REGRESSED"]
        regressions.sort(key=_finding_rank)
        top_regressions = [
            {
                "target_id": f.target_id,
                "hostname": f.hostname,
                "fingerprint": f.fingerprint,
                "severity": f.severity,
                "priority": f.priority,
            }
            for f in regressions[:_TOP_REGRESSIONS_LIMIT]
        ]

        ranked = sorted(open_findings, key=_finding_rank)
        top_findings = [
            {
                "finding_id": f.finding_id,
                "target_id": f.target_id,
                "hostname": f.hostname,
                "fingerprint": f.fingerprint,
                "title": f.title,
                "severity": f.severity,
                "lifecycle_status": f.lifecycle_status,
                "priority": f.priority,
                "remediation_status": f.remediation_status,
            }
            for f in ranked[:_TOP_FINDINGS_LIMIT]
        ]

        events = await repository.history_events(_uuids(target_ids))
        mttr = _mttr(events)
        latest_scan = _latest_completed(scans)
        in_flight = sum(1 for s in scans if s.get("status") in ("QUEUED", "RUNNING"))

        # Remediation rows bound to open identities (for per-status rates).
        open_keys = {(f.target_id, f.fingerprint) for f in open_findings}
        open_remediation = sum(1 for key in open_keys if key in remediation)

        return {
            "targets_total": len(targets),
            "targets_active": sum(1 for t in targets if not t.get("is_archived")),
            "scans_total": counts["total"],
            "scans_completed": counts["completed"],
            "scans_in_flight": in_flight,
            "open_findings_total": len(open_findings),
            "unresolved_identities": unresolved_identities,
            "severity_counts": _tally(f.severity for f in open_findings),
            "priority_counts": _tally(str(f.priority["level"]) for f in open_findings),
            "lifecycle_counts": _tally(f.lifecycle_status for f in open_findings),
            "remediation_counts": remediation_counts,
            "remediation_open_total": open_remediation,
            "done_open_count": done_open_count,
            "done_open_items": done_open,
            "regressions_total": len(regressions),
            "regressions_targets": sorted({f.target_id for f in regressions}),
            "top_regressions": top_regressions,
            "top_findings": top_findings,
            "mttr": mttr,
            "latest_scan": latest_scan,
            "priority_version": PRIORITY_VERSION_V2,
        }

    async def get_trends(self, *, target_id: uuid.UUID | None, limit: int) -> dict[str, object]:
        """Per-scan trend points, oldest first (honest empty when thin)."""
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )

        user_id = self._principal.id
        repository = PostureRepository(self._session)
        targets = await repository.list_owned_targets(user_id)
        owned = {str(t["id"]) for t in targets}
        if target_id is not None:
            if str(target_id) not in owned:
                from src.domain.errors import NotFoundError

                raise NotFoundError()
            wanted: list[object] = [target_id]
        else:
            wanted = [t["id"] for t in targets]

        scans = await repository.list_scans_for_user(user_id, limit=_SCANS_LIST_LIMIT)
        completed = sorted(
            (
                s
                for s in scans
                if s.get("completed_at") is not None
                and str(s.get("target_id")) in {str(w) for w in wanted}
            ),
            key=lambda s: (s["completed_at"], s["created_at"], s["id"]),
        )
        if not completed:
            return {"points": [], "insufficient_history": True}

        chosen = completed[-max(1, min(limit, _MAX_TREND_LIMIT)) :]
        scan_ids = [s["id"] for s in chosen]
        findings = await repository.findings_by_scan(user_id, _uuids(scan_ids))
        lifecycle = await repository.lifecycle_for_scans(_uuids(scan_ids))
        enrichment = await repository.enrichment_map(_uuids([s["target_id"] for s in chosen]))
        technologies = await repository.technologies_map(_uuids([s["target_id"] for s in chosen]))
        resolved_before = await self._resolved_before_map(
            repository, _uuids([s["target_id"] for s in chosen])
        )

        by_target: dict[str, list[dict[str, object]]] = {}
        for scan in chosen:
            by_target.setdefault(str(scan["target_id"]), []).append(scan)

        points: list[dict[str, object]] = []
        for scan in chosen:
            tid = str(scan["target_id"])
            rows = findings.get(str(scan["id"]), [])
            completed_at = scan["completed_at"]
            assert isinstance(completed_at, datetime)
            prior = _previous_scan(by_target[tid], scan)
            prior_rows = findings.get(str(prior["id"]), []) if prior is not None else []
            prior_fps = {str(r["fingerprint"]) for r in prior_rows}
            prior_sev: dict[str, str] = {
                str(r["fingerprint"]): str(r["severity"]) for r in prior_rows
            }
            cur_fps = {str(r["fingerprint"]) for r in rows}
            resolved = prior_fps - cur_fps
            # Regression needs a predecessor scan to be absent from: without
            # one, every finding is new by definition (a later RESOLVED
            # event cannot retroactively regress the first observation).
            regressed = (
                {
                    fp
                    for fp in cur_fps - prior_fps
                    if any(
                        ts < _as_aware(completed_at) for ts in resolved_before.get((tid, fp), [])
                    )
                }
                if prior is not None
                else set()
            )
            lc_map = lifecycle.get(str(scan["id"]), {})
            point_priorities: list[str] = []
            severity_counts: dict[str, int] = {}
            for row in rows:
                fp = str(row["fingerprint"])
                sev = str(row["severity"])
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                enrich = _enrichment_at(enrichment.get((tid, fp), []), _as_aware(completed_at))
                tech = _technologies_at(technologies.get(tid, []), _as_aware(completed_at))
                snapshot = _priority_snapshot(
                    severity=sev,
                    lifecycle_status=lc_map.get(fp),
                    previous_severity=prior_sev.get(fp),
                    enrichment_rows=enrich,
                    technologies=tech,
                )
                point_priorities.append(str(snapshot["level"]))
            points.append(
                {
                    "scan_id": str(scan["id"]),
                    "target_id": tid,
                    "completed_at": _iso(completed_at),
                    "status": str(scan.get("status")),
                    "total_findings": len(rows),
                    "severity_counts": severity_counts,
                    "priority_counts": _tally(point_priorities),
                    "new_count": len(cur_fps - prior_fps - regressed),
                    "resolved_count": len(resolved),
                    "regressed_count": len(regressed),
                }
            )
        return {
            "points": points,
            "insufficient_history": len(points) < 2,
            "priority_version": PRIORITY_VERSION_V2,
        }

    async def get_targets_posture(self, *, limit: int) -> dict[str, object]:
        """Per-target posture cards, most-recently-scanned first."""
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )

        user_id = self._principal.id
        repository = PostureRepository(self._session)
        targets = await repository.list_owned_targets(user_id)
        scans = await repository.list_scans_for_user(user_id, limit=_SCANS_LIST_LIMIT)
        hostnames = {str(t["id"]): str(t["hostname"]) for t in targets}

        open_findings, _unresolved = await self._open_findings(
            [t["id"] for t in targets], hostnames
        )
        by_target: dict[str, list[_OpenFinding]] = {}
        for finding in open_findings:
            by_target.setdefault(finding.target_id, []).append(finding)
        remediation = await repository.remediation_map(_uuids([t["id"] for t in targets]))

        # Most-recently-scanned first (datetime-aware sort, never string
        # comparison across offsets); never-scanned targets last by id.
        ordered: list[tuple[datetime | None, str, dict[str, object]]] = []
        for target in targets:
            tid = str(target["id"])
            own_scans = sorted(
                (
                    s
                    for s in scans
                    if str(s.get("target_id")) == tid and s.get("completed_at") is not None
                ),
                key=lambda s: (s["completed_at"], s["created_at"], s["id"]),
            )
            latest = own_scans[-1] if own_scans else None
            previous = own_scans[-2] if len(own_scans) > 1 else None
            findings = by_target.get(tid, [])
            remediation_counts = _tally(
                str(remediation[(tid, f.fingerprint)]["status"])
                for f in findings
                if (tid, f.fingerprint) in remediation
            )
            done_open = sum(
                1
                for f in findings
                if (tid, f.fingerprint) in remediation
                and remediation[(tid, f.fingerprint)]["status"] == "DONE"
            )
            completed_at = latest["completed_at"] if latest else None
            assert completed_at is None or isinstance(completed_at, datetime)
            ordered.append(
                (
                    completed_at,
                    tid,
                    {
                        "target_id": tid,
                        "hostname": str(target["hostname"]),
                        "is_archived": bool(target.get("is_archived")),
                        "latest_scan": (
                            {
                                "scan_id": str(latest["id"]),
                                "status": str(latest.get("status")),
                                "completed_at": _iso(
                                    latest["completed_at"]
                                    if isinstance(latest["completed_at"], datetime)
                                    else None
                                ),
                            }
                            if latest is not None
                            else None
                        ),
                        "previous_scan_id": str(previous["id"]) if previous else None,
                        "last_scan_at": _iso(
                            latest["completed_at"]
                            if latest is not None and isinstance(latest["completed_at"], datetime)
                            else None
                        ),
                        "open_findings_total": len(findings),
                        "severity_counts": _tally(f.severity for f in findings),
                        "priority_counts": _tally(str(f.priority["level"]) for f in findings),
                        "regressions_count": sum(
                            1 for f in findings if f.lifecycle_status == "REGRESSED"
                        ),
                        "remediation_counts": remediation_counts,
                        "done_open_count": done_open,
                    },
                )
            )
        ordered.sort(
            key=lambda item: (
                item[0] is None,
                -(item[0].timestamp() if item[0] is not None else 0.0),
                item[1],
            )
        )
        cards = [card for _when, _tid, card in ordered]
        capped = cards[: max(1, min(limit, _MAX_TARGETS_LIMIT))]
        return {
            "targets": capped,
            "total": len(cards),
            "priority_version": PRIORITY_VERSION_V2,
        }

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    async def _open_findings(
        self, target_ids: list[object], hostnames: dict[str, str]
    ) -> tuple[list[_OpenFinding], int]:
        """Score every open identity (shared by posture and target views).

        Returns (findings, unresolved_identities): identities with
        lifecycle history but no fingerprinted finding row are counted,
        never guessed at.
        """
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )

        user_id = self._principal.id
        repository = PostureRepository(self._session)
        uuids = _uuids(target_ids)
        lifecycle = await repository.latest_lifecycle_map(uuids)
        finding_rows = await repository.latest_findings_map(user_id, uuids)
        remediation = await repository.remediation_map(uuids)
        tech = await repository.technologies_map(uuids)
        enrichment_all = await repository.enrichment_map(uuids)

        # Previous-scan severities for the severity-change modifier: one
        # batched load of the latest + previous completed scans per target.
        scans = await repository.list_scans_for_user(user_id, limit=_SCANS_LIST_LIMIT)
        latest_ids: list[object] = []
        previous_ids: list[object] = []
        for tid in {str(t) for t in target_ids}:
            own = sorted(
                (
                    s
                    for s in scans
                    if str(s.get("target_id")) == tid and s.get("completed_at") is not None
                ),
                key=lambda s: (s["completed_at"], s["created_at"], s["id"]),
            )
            if own:
                latest_ids.append(own[-1]["id"])
            if len(own) > 1:
                previous_ids.append(own[-2]["id"])
        prior_rows = await repository.findings_by_scan(user_id, _uuids(latest_ids + previous_ids))
        prior_sev: dict[tuple[str, str], str] = {}
        for tid in {str(t) for t in target_ids}:
            own = sorted(
                (
                    s
                    for s in scans
                    if str(s.get("target_id")) == tid and s.get("completed_at") is not None
                ),
                key=lambda s: (s["completed_at"], s["created_at"], s["id"]),
            )
            if len(own) > 1:
                for row in prior_rows.get(str(own[-2]["id"]), []):
                    prior_sev[(tid, str(row["fingerprint"]))] = str(row["severity"])

        findings: list[_OpenFinding] = []
        unresolved_identities = 0
        for (tid, fp), life in lifecycle.items():
            if life["status"] not in OPEN_STATUSES:
                continue
            finding_row = finding_rows.get((tid, fp))
            if finding_row is None:
                # Lifecycle history without a fingerprinted finding row
                # (pre-identity data): counted, never guessed at.
                unresolved_identities += 1
                continue
            tech_slugs = tuple(await self._tech_slugs(tech, tid))
            snapshot = _priority_snapshot(
                severity=str(finding_row["severity"]),
                lifecycle_status=str(life["status"]),
                previous_severity=prior_sev.get((tid, fp)),
                enrichment_rows=enrichment_all.get((tid, fp), []),
                technologies=tech_slugs,
            )
            remediation_row = remediation.get((tid, fp))
            findings.append(
                _OpenFinding(
                    target_id=tid,
                    hostname=hostnames.get(tid, ""),
                    fingerprint=fp,
                    finding_id=str(finding_row["finding_id"]),
                    scan_id=str(finding_row["scan_id"]),
                    title=str(finding_row["title"]),
                    severity=str(finding_row["severity"]),
                    lifecycle_status=str(life["status"]),
                    previous_severity=prior_sev.get((tid, fp)),
                    priority=snapshot,
                    remediation_status=str(remediation_row["status"]) if remediation_row else None,
                )
            )
        return findings, unresolved_identities

    async def _tech_slugs(self, tech: dict[str, list[dict[str, object]]], tid: str) -> list[str]:
        return [str(r["slug"]) for r in tech.get(tid, []) if r.get("slug")]

    async def _resolved_before_map(
        self, repository: Any, target_ids: list[Any]
    ) -> dict[tuple[str, str], list[datetime]]:
        """RESOLVED effective_ats per (target, fingerprint), ascending."""
        events = await repository.history_events(target_ids)
        out: dict[tuple[str, str], list[datetime]] = {}
        for event in events:
            if str(event.get("status")) != "RESOLVED":
                continue
            moment = event.get("effective_at")
            if not isinstance(moment, datetime):
                continue
            out.setdefault((str(event["target_id"]), str(event["fingerprint"])), []).append(
                _as_aware(moment)
            )
        return out


def _uuids(values: list[object]) -> list[Any]:
    import uuid as uuid_module

    out: list[Any] = []
    for value in values:
        if isinstance(value, uuid_module.UUID):
            out.append(value)
        else:
            out.append(uuid_module.UUID(str(value)))
    return out


def _as_uuid(value: str) -> Any:
    import uuid as uuid_module

    return uuid_module.UUID(value)


def _coerce_dt(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _tally(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _finding_rank(finding: _OpenFinding) -> tuple[int, int, str]:
    score = finding.priority.get("score")
    return (
        -(score if isinstance(score, int) else 0),
        -_SEVERITY_ORDER.get(finding.severity, 0),
        finding.fingerprint,
    )


def _latest_completed(scans: list[dict[str, object]]) -> dict[str, object] | None:
    completed = [s for s in scans if s.get("completed_at") is not None]
    if not completed:
        return None
    latest = max(completed, key=lambda s: (s["completed_at"], s["created_at"], s["id"]))
    completed_at = latest["completed_at"]
    return {
        "scan_id": str(latest["id"]),
        "target_id": str(latest["target_id"]),
        "status": str(latest.get("status")),
        "completed_at": _iso(completed_at if isinstance(completed_at, datetime) else None),
    }


def _previous_scan(
    ordered: list[dict[str, object]], scan: dict[str, object]
) -> dict[str, object] | None:
    ids = [str(s["id"]) for s in ordered]
    try:
        index = ids.index(str(scan["id"]))
    except ValueError:
        return None
    return ordered[index - 1] if index > 0 else None


def _mttr(events: list[dict[str, object]]) -> dict[str, object] | None:
    """Mean/median hours from first NEW to first later RESOLVED.

    Per (target, fingerprint): the earliest NEW event starts the clock;
    the first RESOLVED event strictly after it stops it. Identities that
    never resolve are excluded from the sample (counted as unresolved).
    No sample means null — never a fabricated zero.
    """
    first_new: dict[tuple[str, str], datetime] = {}
    resolved_hours: list[float] = []
    resolved_identities = 0
    for event in events:
        key = (str(event["target_id"]), str(event["fingerprint"]))
        moment = event.get("effective_at")
        if not isinstance(moment, datetime):
            continue
        status = str(event.get("status"))
        if status == "NEW" and key not in first_new:
            first_new[key] = _as_aware(moment)
        elif status == "RESOLVED" and key in first_new:
            start = first_new.pop(key)
            end = _as_aware(moment)
            if end >= start:
                resolved_hours.append((end - start).total_seconds() / 3600.0)
                resolved_identities += 1
    if not resolved_hours:
        return None
    resolved_hours.sort()
    return {
        "mean_hours": round(mean(resolved_hours), 2),
        "median_hours": round(median(resolved_hours), 2),
        "sample_size": len(resolved_hours),
        "resolved_identities": resolved_identities,
    }

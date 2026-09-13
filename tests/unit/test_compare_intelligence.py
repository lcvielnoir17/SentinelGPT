"""Comparison intelligence: deterministic per-finding change records.

Extends the four-bucket ``compare_scans`` classification (shared engine,
unchanged legacy output) with severity / priority / remediation /
evidence / enrichment transitions, lifecycle states, first/last seen,
and an aggregate summary — the AI-ready representation a future analyst
may narrate but must never recompute.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src.domain.errors import InvalidScanStateError, NotFoundError
from src.domain.scans.scan_service import (
    ScanService,
    _priority_changed,
    _remediation_transition,
)
from tests.unit.conftest import _principal  # noqa: F401 — shared harness

TARGET = uuid.uuid4()

FP_NEW = "fp-compare-new"
FP_PERS = "fp-compare-persistent"
FP_RES = "fp-compare-resolved"
FP_REGR = "fp-compare-regressed"
FP_SAME = "fp-compare-same"

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T0_5 = datetime(2026, 1, 2, tzinfo=UTC)
T1 = datetime(2026, 2, 1, tzinfo=UTC)  # scan A completion
T2 = datetime(2026, 3, 1, tzinfo=UTC)
T3 = datetime(2026, 4, 1, tzinfo=UTC)  # scan B completion


def _scan(sid: uuid.UUID, owner_id: uuid.UUID, target_id: uuid.UUID = TARGET) -> object:
    completed = T3 if sid != SCAN_A else T1
    created = T3 - timedelta(days=1) if sid != SCAN_A else T0
    return type(
        "S",
        (),
        {
            "id": sid,
            "target_id": target_id,
            "initiated_by_user_id": owner_id,
            "parent_scan_id": None,
            "completed_at": completed,
            "created_at": created,
        },
    )()


SCAN_A = uuid.uuid4()
SCAN_B = uuid.uuid4()

_FIDS: dict[tuple[str, str], uuid.UUID] = {}


def _fid(scan_tag: str, fp: str) -> uuid.UUID:
    key = (scan_tag, fp)
    if key not in _FIDS:
        _FIDS[key] = uuid.uuid4()
    return _FIDS[key]


def _index_for(scan_tag: str) -> dict[str, tuple[uuid.UUID, str, str, str]]:
    if scan_tag == "a":
        return {
            FP_PERS: (_fid("a", FP_PERS), "Persistent", "MEDIUM", "MISSING_SECURITY_HEADER"),
            FP_RES: (_fid("a", FP_RES), "Resolved", "LOW", "MISSING_SECURITY_HEADER"),
            FP_SAME: (_fid("a", FP_SAME), "Same", "HIGH", "MISSING_SECURITY_HEADER"),
        }
    return {
        FP_PERS: (_fid("b", FP_PERS), "Persistent", "HIGH", "MISSING_SECURITY_HEADER"),
        FP_NEW: (_fid("b", FP_NEW), "New", "HIGH", "MISSING_SECURITY_HEADER"),
        FP_SAME: (_fid("b", FP_SAME), "Same", "HIGH", "MISSING_SECURITY_HEADER"),
        FP_REGR: (_fid("b", FP_REGR), "Regressed", "MEDIUM", "MISSING_SECURITY_HEADER"),
    }


class _CompareSeams:
    """Deterministic doubles for every batch seam the detailed path uses."""

    def __init__(self, owner_id: uuid.UUID) -> None:
        self.owner_id = owner_id
        self.resolved_history: set[str] = {FP_REGR}
        self.prev_lifecycle = {FP_PERS: "PERSISTENT", FP_RES: "PERSISTENT", FP_SAME: "NEW"}
        self.bounds = {
            fp: {"first_seen": T0, "last_seen": T3}
            for fp in (FP_NEW, FP_PERS, FP_RES, FP_REGR, FP_SAME)
        }
        self.enrichment: dict[str, list[dict[str, object]]] = {}
        self.remediation: dict[str, dict[str, object]] = {}
        self.evidence: dict[str, list[dict[str, str]]] = {}
        self.technologies: list[dict[str, object]] = []

    async def visible(self, sid: uuid.UUID) -> object:
        if sid == SCAN_A:
            return _scan(SCAN_A, self.owner_id)
        if sid == SCAN_B:
            return _scan(SCAN_B, self.owner_id)
        raise NotFoundError()

    async def index(self, sid: uuid.UUID) -> dict:
        if sid == SCAN_A:
            return _index_for("a")
        if sid == SCAN_B:
            return _index_for("b")
        return {}

    async def with_status(
        self,
        *,
        target_id: uuid.UUID,  # noqa: ARG002 - fake honors fingerprints only
        fingerprints: set[str],
        status_id: int,  # noqa: ARG002 - fake honors fingerprints only
    ) -> set[str]:
        return {fp for fp in fingerprints if fp in self.resolved_history}

    async def prev_lifecycle_in_scan(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,  # noqa: ARG002 - canned map
        scan_id: uuid.UUID,  # noqa: ARG002 - canned map
    ) -> dict[str, str]:
        return {fp: self.prev_lifecycle[fp] for fp in fingerprints if fp in self.prev_lifecycle}

    async def occurrence_bounds(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,  # noqa: ARG002 - canned map
        user_id: uuid.UUID,  # noqa: ARG002 - canned map
    ) -> dict[str, dict[str, object]]:
        return {fp: self.bounds[fp] for fp in fingerprints if fp in self.bounds}

    async def remediation_states(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,  # noqa: ARG002 - canned map
    ) -> dict[str, dict[str, object]]:
        return {fp: self.remediation[fp] for fp in fingerprints if fp in self.remediation}

    async def list_enrichment(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,  # noqa: ARG002 - canned map
    ) -> dict:
        return {fp: self.enrichment[fp] for fp in fingerprints if fp in self.enrichment}

    async def list_evidence(self, finding_ids: list[str]) -> dict:
        return {fid: self.evidence[fid] for fid in finding_ids if fid in self.evidence}

    async def list_technologies(self, target_id: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG002 - canned rows
        return list(self.technologies)


def _service(monkeypatch: pytest.MonkeyPatch, seams: _CompareSeams) -> ScanService:
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from src.infrastructure.database.repositories.target_repository import TargetRepository

    async def fake_status_ids(_s: object) -> dict[str, int]:
        return {"NEW": 1, "PERSISTENT": 2, "RESOLVED": 3, "REGRESSED": 4}

    async def _visible(_self: object, sid: uuid.UUID) -> object:
        return await seams.visible(sid)

    async def _index(_self: object, sid: uuid.UUID) -> dict:
        return await seams.index(sid)

    async def _with_status(_self: object, **kwargs: object) -> set[str]:
        return await seams.with_status(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(ScanService, "_fingerprint_index", _index)
    monkeypatch.setattr(ScanService, "_fingerprints_with_status", _with_status)
    monkeypatch.setattr(ScanService, "_previous_lifecycle_in_scan", seams.prev_lifecycle_in_scan)
    monkeypatch.setattr(ScanService, "_occurrence_bounds", seams.occurrence_bounds)
    monkeypatch.setattr(ScanService, "_remediation_states", seams.remediation_states)
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_enrichment_for_fingerprints", seams.list_enrichment
    )
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_evidence_for_findings", seams.list_evidence
    )
    monkeypatch.setattr(TargetRepository, "list_technologies", seams.list_technologies)
    monkeypatch.setattr("src.domain.scans.scan_service._lifecycle_status_ids", fake_status_ids)
    return ScanService(object(), _principal(seams.owner_id))  # type: ignore[arg-type]


def _rec(result: dict[str, object], fp: str) -> dict[str, object]:
    records = [r for r in result["records"] if r["fingerprint"] == fp]  # type: ignore[union-attr]
    assert len(records) == 1, f"expected one record for {fp}"
    return records[0]


# --------------------------------------------------------------------------- #
# Buckets & severity                                                          #
# --------------------------------------------------------------------------- #


async def test_no_differences_all_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    """Identical fingerprints and severities: nothing changed anywhere."""
    seams = _CompareSeams(uuid.uuid4())
    seams.resolved_history = set()
    service = _service(monkeypatch, seams)

    async def only_same(_self: object, sid: uuid.UUID) -> dict:
        return {FP_SAME: _index_for("a" if sid == SCAN_A else "b")[FP_SAME]}

    monkeypatch.setattr(ScanService, "_fingerprint_index", only_same)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    assert result["summary"]["persistent_count"] == 1
    assert result["summary"]["severity_changed_count"] == 0
    assert result["summary"]["priority_changed_count"] == 0
    assert result["summary"]["evidence_changed_count"] == 0
    record = _rec(result, FP_SAME)
    assert record["severity_changed"] is False
    assert record["previous_severity"] == "HIGH"
    assert record["priority_changed"] is False
    assert record["previous_priority"] == record["priority"]


async def test_new_finding_has_no_previous_values(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    seams.enrichment[FP_NEW] = [
        {
            "source": "curated",
            "external_ref": "CVE-2014-0160",
            "cve_id": "CVE-2014-0160",
            "cwe_id": "CWE-125",
            "cvss_score": 7.5,
            "created_at": T2,
        }
    ]
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_NEW)
    assert record["lifecycle_status"] == "NEW"
    assert record["previous_severity"] is None
    assert record["previous_priority"] is None
    assert record["previous_lifecycle_status"] is None
    assert record["severity_changed"] is False
    assert record["priority_changed"] is False
    assert record["cves"] == ["CVE-2014-0160"]
    assert record["cvss_max"] == 7.5
    assert record["enrichment_changed"] is True
    # NEW + HIGH priority combination (v2: 60 base + 5 CVE + 5 CVSS>=7).
    assert record["priority"]["level"] == "P2"
    assert record["priority"]["score"] == 70
    assert record["priority"]["version"] == "sgpt.priority.v2"


async def test_persistent_severity_increase(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same fingerprint MEDIUM → HIGH stays PERSISTENT with a change flag."""
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_PERS)
    assert record["lifecycle_status"] == "PERSISTENT"
    assert record["severity"] == "HIGH"
    assert record["previous_severity"] == "MEDIUM"
    assert record["severity_changed"] is True
    assert record["fingerprint"] == FP_PERS
    # Priority follows severity deterministically: P3(40) → P2(60).
    assert record["previous_priority"]["level"] == "P3"
    assert record["priority"]["level"] == "P2"
    assert record["priority_changed"] is True


async def test_persistent_severity_decrease(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)

    async def swapped(_self: object, sid: uuid.UUID) -> dict:
        base = _index_for("a" if sid == SCAN_A else "b")
        fid, title, _sev, cat = base[FP_PERS]
        base = dict(base)
        base[FP_PERS] = (fid, title, "HIGH" if sid == SCAN_A else "LOW", cat)
        return base

    monkeypatch.setattr(ScanService, "_fingerprint_index", swapped)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_PERS)
    assert record["severity"] == "LOW"
    assert record["previous_severity"] == "HIGH"
    assert record["severity_changed"] is True
    assert record["priority"]["score"] < record["previous_priority"]["score"]


async def test_resolved_finding_carries_previous_state(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    seams.remediation[FP_RES] = {
        "status": "DONE",
        "created_at": T0,
        "updated_at": T2,
    }
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_RES)
    assert record["lifecycle_status"] == "RESOLVED"
    assert record["previous_lifecycle_status"] == "PERSISTENT"
    assert record["severity"] == "LOW"
    assert record["previous_severity"] == "LOW"
    assert record["severity_changed"] is False
    # Resolved needs nothing: current priority is NONE/0.
    assert record["priority"] == {
        "score": 0,
        "level": "NONE",
        "version": record["priority"]["version"],
        "factors": ["resolved"],
    }
    assert record["previous_priority"]["level"] == "P4"
    assert record["priority_changed"] is True
    # RESOLVED + remediation DONE coexist without conflation.
    assert record["remediation_status"] == "DONE"
    assert record["remediation_changed"] is True
    assert record["previous_remediation_status"] is None


async def test_regression_with_priority_increase(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_REGR)
    assert record["lifecycle_status"] == "REGRESSED"
    assert record["previous_lifecycle_status"] is None
    assert record["previous_severity"] is None
    # REGRESSED bonus (+15) on MEDIUM base (40) → 55/P2.
    assert record["priority"]["score"] == 55
    assert record["priority"]["level"] == "P2"
    assert record["priority_changed"] is False


# --------------------------------------------------------------------------- #
# Priority versions                                                           #
# --------------------------------------------------------------------------- #


def test_priority_version_mismatch_is_explicit() -> None:
    """Different engine versions are exposed, never silently compared."""
    current = {"score": 60, "level": "P2", "version": "sgpt.priority.v2"}
    previous = {"score": 60, "level": "P2", "version": "sgpt.priority.v1"}
    changed, match = _priority_changed(current, previous)
    assert changed is False
    assert match is False


def test_priority_changed_detects_score_and_level() -> None:
    changed, match = _priority_changed(
        {"score": 60, "level": "P2", "version": "v"},
        {"score": 40, "level": "P3", "version": "v"},
    )
    assert (changed, match) == (True, True)
    assert _priority_changed({"score": 40, "level": "P3", "version": "v"}, None) == (False, True)


async def test_priority_increase_from_later_enrichment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same severity, CVE advisory added after scan A → priority rises."""
    seams = _CompareSeams(uuid.uuid4())
    seams.enrichment[FP_SAME] = [
        {
            "source": "curated",
            "external_ref": "CVE-2021-44228",
            "cve_id": "CVE-2021-44228",
            "cwe_id": None,
            "cvss_score": None,
            "created_at": T2,
        }
    ]
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_SAME)
    assert record["previous_priority"]["score"] == 60  # HIGH, no signals at A
    assert record["priority"]["score"] == 65  # +5 known CVE
    assert record["priority_changed"] is True
    assert record["enrichment_changed"] is True


async def test_technology_relevance_in_records(monkeypatch: pytest.MonkeyPatch) -> None:
    """Paired tech+CVE evidence adds the v2 relevance bonus per side."""
    seams = _CompareSeams(uuid.uuid4())
    seams.technologies = [
        {"slug": "nginx", "first_observed_at": T0.isoformat()},
    ]
    seams.enrichment[FP_PERS] = [
        {
            "source": "curated",
            "external_ref": "CVE-2021-44228",
            "cve_id": "CVE-2021-44228",
            "cwe_id": None,
            "cvss_score": None,
            "affected_technology": "nginx HTTP server",
            "created_at": T0,
        }
    ]
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_PERS)
    # HIGH(60) + CVE(5) + tech(5) = 70; previous MEDIUM(40) + CVE(5) + tech(5) = 50.
    assert record["priority"]["score"] == 70
    assert record["previous_priority"]["score"] == 50
    assert record["priority_changed"] is True
    assert "tech-relevance:nginx=+5" in record["priority"]["factors"]


async def test_technology_first_seen_after_scan_a_ignored_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tech observed only after scan A cannot describe scan-A state."""
    seams = _CompareSeams(uuid.uuid4())
    seams.technologies = [
        {"slug": "nginx", "first_observed_at": T2.isoformat()},
    ]
    seams.enrichment[FP_PERS] = [
        {
            "source": "curated",
            "external_ref": "CVE-2021-44228",
            "cve_id": "CVE-2021-44228",
            "cwe_id": None,
            "cvss_score": None,
            "affected_technology": "nginx HTTP server",
            "created_at": T0,
        }
    ]
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_PERS)
    assert record["priority"]["score"] == 70  # current side sees nginx
    assert record["previous_priority"]["score"] == 45  # MEDIUM + CVE, no tech
    assert record["priority_changed"] is True


# --------------------------------------------------------------------------- #
# Remediation                                                                 #
# --------------------------------------------------------------------------- #


def test_remediation_transition_rules() -> None:
    """Timestamp inference: unknown pasts stay None, never invented."""
    # Modified after scan A: changed, previous unknown.
    assert _remediation_transition(
        {"status": "DONE", "created_at": T0, "updated_at": T2}, T1, existed_at_a=True
    ) == (None, True)
    # Stable since before scan A: previous known, unchanged.
    assert _remediation_transition(
        {"status": "IN_PROGRESS", "created_at": T0, "updated_at": T0_5},
        T1,
        existed_at_a=True,
    ) == ("IN_PROGRESS", False)
    # Created after scan A: did not exist then.
    assert _remediation_transition(
        {"status": "TODO", "created_at": T2, "updated_at": T2}, T1, existed_at_a=True
    ) == (None, True)
    # No row, or no previous side: quiet.
    assert _remediation_transition(None, T1, existed_at_a=True) == (None, False)
    assert _remediation_transition(
        {"status": "DONE", "created_at": T0, "updated_at": T2}, T1, existed_at_a=False
    ) == (None, False)


async def test_remediation_transition_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    seams.remediation[FP_PERS] = {"status": "DONE", "created_at": T0, "updated_at": T2}
    seams.remediation[FP_SAME] = {"status": "IN_PROGRESS", "created_at": T0, "updated_at": T0_5}
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    changed = _rec(result, FP_PERS)
    assert changed["remediation_status"] == "DONE"
    assert changed["previous_remediation_status"] is None
    assert changed["remediation_changed"] is True
    # DONE remediation while the finding is still PERSISTENT: distinct axes.
    assert changed["lifecycle_status"] == "PERSISTENT"

    stable = _rec(result, FP_SAME)
    assert stable["remediation_status"] == "IN_PROGRESS"
    assert stable["previous_remediation_status"] == "IN_PROGRESS"
    assert stable["remediation_changed"] is False


# --------------------------------------------------------------------------- #
# Evidence & enrichment                                                       #
# --------------------------------------------------------------------------- #


def _ev(scan_tag: str, fp: str, *contents: str) -> list[dict[str, str]]:
    return [
        {"id": str(uuid.uuid4()), "type": "TOOL_OUTPUT_SNIPPET", "content": c} for c in contents
    ]


async def test_evidence_change_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    seams.evidence[str(_fid("a", FP_PERS))] = _ev("a", FP_PERS, "header missing")
    seams.evidence[str(_fid("b", FP_PERS))] = _ev("b", FP_PERS, "header STILL missing")
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_PERS)
    assert record["evidence_count"] == 1
    assert record["previous_evidence_count"] == 1
    assert record["evidence_changed"] is True
    assert len(record["evidence_hashes"]) == 1


async def test_identical_evidence_is_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    seams.evidence[str(_fid("a", FP_SAME))] = _ev("a", FP_SAME, "same body")
    seams.evidence[str(_fid("b", FP_SAME))] = _ev("b", FP_SAME, "same body")
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_SAME)
    assert record["evidence_changed"] is False
    assert record["evidence_count"] == 1
    assert record["previous_evidence_count"] == 1


async def test_enrichment_activated_between_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    seams.enrichment[FP_PERS] = [
        {
            "source": "curated",
            "external_ref": "CVE-2021-44228",
            "cve_id": "CVE-2021-44228",
            "cwe_id": "CWE-319",
            "cvss_score": 9.8,
            "created_at": T2,
        }
    ]
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)

    record = _rec(result, FP_PERS)
    assert record["enrichment_changed"] is True
    assert record["cves"] == ["CVE-2021-44228"]
    assert record["cvss_max"] == 9.8
    # Severe CVSS (+10) and CVE (+5) stack on HIGH (60) → 75/P1.
    assert record["priority"]["score"] == 75
    assert record["priority"]["level"] == "P1"
    # At scan-A time the advisory did not exist: MEDIUM base only.
    assert record["previous_priority"]["score"] == 40
    assert record["previous_priority"]["level"] == "P3"


# --------------------------------------------------------------------------- #
# Determinism, linkage, gates                                                 #
# --------------------------------------------------------------------------- #


async def test_records_deterministically_ordered(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    first = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    second = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    assert first == second
    # Bucket order is new → persistent → resolved → regressed, sorted within.
    statuses = [r["lifecycle_status"] for r in first["records"]]
    assert statuses == ["NEW", "PERSISTENT", "PERSISTENT", "RESOLVED", "REGRESSED"]


async def test_summary_counts_come_from_records(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    summary = result["summary"]
    assert summary["new_count"] == 1
    assert summary["persistent_count"] == 2
    assert summary["resolved_count"] == 1
    assert summary["regressed_count"] == 1
    assert summary["severity_changed_count"] == 1
    assert summary["priority_changed_count"] >= 1
    total = (
        summary["new_count"]
        + summary["persistent_count"]
        + summary["resolved_count"]
        + summary["regressed_count"]
    )
    assert total == len(result["records"])


async def test_legacy_buckets_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    """The detailed view carries the unchanged legacy bucket shape."""
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    assert {i["fingerprint"] for i in result["new"]} == {FP_NEW}
    assert {i["fingerprint"] for i in result["persistent"]} == {FP_PERS, FP_SAME}
    assert {i["fingerprint"] for i in result["resolved"]} == {FP_RES}
    assert {i["fingerprint"] for i in result["regressed"]} == {FP_REGR}


async def test_previous_scan_linkage(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    for record in result["records"]:
        if record["lifecycle_status"] == "RESOLVED":
            assert record["scan_id"] == str(SCAN_A)
            assert record["previous_scan_id"] is None  # A has no parent here
        else:
            assert record["scan_id"] == str(SCAN_B)
            assert record["previous_scan_id"] == str(SCAN_A)


async def test_first_and_last_seen_from_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    result = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    record = _rec(result, FP_PERS)
    assert record["first_seen_at"] == T0.isoformat()
    assert record["last_seen_at"] == T3.isoformat()


async def test_same_target_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)

    async def other_target(self: object, sid: uuid.UUID) -> object:
        row = await seams.visible(sid)
        if sid == SCAN_B:
            row.target_id = uuid.uuid4()
        return row

    monkeypatch.setattr(ScanService, "_get_visible_scan", other_target)
    with pytest.raises(InvalidScanStateError):
        await service.compare_scans_detailed(SCAN_A, SCAN_B)


async def test_cross_owner_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    _service(monkeypatch, seams)
    from src.domain.users.user_service import UserAccount

    async def gated(self: object, sid: uuid.UUID) -> object:
        if self._principal.id != seams.owner_id:  # type: ignore[union-attr]
            raise NotFoundError()
        return await seams.visible(sid)

    monkeypatch.setattr(ScanService, "_get_visible_scan", gated)
    intruder = UserAccount(id=uuid.uuid4(), email="x@example.com", created_at=T0)
    intruder_service = ScanService(object(), intruder)  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        await intruder_service.compare_scans_detailed(SCAN_A, SCAN_B)


async def test_invalid_scans_are_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)
    with pytest.raises(NotFoundError):
        await service.compare_scans_detailed(SCAN_A, uuid.uuid4())


async def test_empty_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty B → everything resolved; empty A → everything new."""
    seams = _CompareSeams(uuid.uuid4())
    service = _service(monkeypatch, seams)

    async def empty_b(_self: object, sid: uuid.UUID) -> dict:
        return _index_for("a") if sid == SCAN_A else {}

    monkeypatch.setattr(ScanService, "_fingerprint_index", empty_b)
    emptied = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    assert emptied["summary"]["resolved_count"] == 3
    assert emptied["summary"]["new_count"] == 0
    assert all(r["lifecycle_status"] == "RESOLVED" for r in emptied["records"])

    async def empty_a(_self: object, sid: uuid.UUID) -> dict:
        return {} if sid == SCAN_A else _index_for("b")

    monkeypatch.setattr(ScanService, "_fingerprint_index", empty_a)
    fresh = await service.compare_scans_detailed(SCAN_A, SCAN_B)
    assert fresh["summary"]["new_count"] == 3
    assert fresh["summary"]["regressed_count"] == 1
    assert all(r["previous_severity"] is None for r in fresh["records"])


# --------------------------------------------------------------------------- #
# HTTP envelope                                                               #
# --------------------------------------------------------------------------- #


@pytest.fixture
def compare_client(monkeypatch: pytest.MonkeyPatch):
    from src.api.dependencies import get_current_user
    from src.main import create_application

    seams = _CompareSeams(uuid.uuid4())
    service_owner = seams.owner_id

    async def visible(self: object, sid: uuid.UUID) -> object:
        return await seams.visible(sid)

    async def fake_status_ids(_s: object) -> dict[str, int]:
        return {"NEW": 1, "PERSISTENT": 2, "RESOLVED": 3, "REGRESSED": 4}

    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )

    monkeypatch.setattr(ScanService, "_get_visible_scan", visible)
    monkeypatch.setattr(ScanService, "_fingerprint_index", seams.index)
    monkeypatch.setattr(ScanService, "_fingerprints_with_status", seams.with_status)
    monkeypatch.setattr(ScanService, "_previous_lifecycle_in_scan", seams.prev_lifecycle_in_scan)
    monkeypatch.setattr(ScanService, "_occurrence_bounds", seams.occurrence_bounds)
    monkeypatch.setattr(ScanService, "_remediation_states", seams.remediation_states)
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_enrichment_for_fingerprints", seams.list_enrichment
    )
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_evidence_for_findings", seams.list_evidence
    )
    monkeypatch.setattr(TargetRepository, "list_technologies", seams.list_technologies)
    monkeypatch.setattr("src.domain.scans.scan_service._lifecycle_status_ids", fake_status_ids)
    app = create_application()
    app.dependency_overrides[get_current_user] = lambda: _principal(service_owner)
    return TestClient(app)


def test_compare_http_envelope_has_records_and_summary(compare_client: TestClient) -> None:
    response = compare_client.get(f"/api/v1/scans/{SCAN_A}/compare/{SCAN_B}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) >= {"new", "persistent", "resolved", "regressed", "records", "summary"}
    assert body["summary"]["newCount"] == 1
    assert body["summary"]["persistentCount"] == 2
    record = next(r for r in body["records"] if r["fingerprint"] == FP_PERS)
    assert record["severityChanged"] is True
    assert record["previousSeverity"] == "MEDIUM"
    assert record["lifecycleStatus"] == "PERSISTENT"
    assert record["priority"]["level"] == "P2"
    assert record["priorityVersionsMatch"] is True
    assert record["priority"]["version"] == "sgpt.priority.v2"


def test_compare_http_cross_owner_is_404(compare_client: TestClient) -> None:
    assert compare_client.get(f"/api/v1/scans/{uuid.uuid4()}/compare/{SCAN_B}").status_code == 404

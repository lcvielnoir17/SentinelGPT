"""Security posture read models: deterministic metrics over canonical data.

Posture derives from targets, scans, findings, lifecycle history,
remediation, enrichment, and technology rows — nothing else. Tests pin
every metric definition with canned repository doubles: counts,
priority integration (v2), trends, MTTR honesty, and owner isolation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src.domain.errors import NotFoundError
from src.domain.posture.posture_service import PostureService
from tests.unit.conftest import _principal  # noqa: F401 — shared harness

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 2, 1, tzinfo=UTC)
T1_5 = datetime(2026, 2, 15, tzinfo=UTC)
T2 = datetime(2026, 3, 1, tzinfo=UTC)

OWNER = uuid.uuid4()
T1_ID = uuid.uuid4()
T2_ID = uuid.uuid4()
T3_ID = uuid.uuid4()
S1_ID = uuid.uuid4()
S2_ID = uuid.uuid4()
S3_ID = uuid.uuid4()


def _target(tid: uuid.UUID, hostname: str, archived: bool = False) -> dict:
    return {
        "id": str(tid),
        "hostname": hostname,
        "normalized_url": f"https://{hostname}/",
        "is_archived": archived,
        "created_at": T0,
    }


def _scan(sid: uuid.UUID, tid: uuid.UUID, status: str, completed: datetime | None) -> dict:
    return {
        "id": str(sid),
        "target_id": str(tid),
        "status": status,
        "parent_scan_id": None,
        "completed_at": completed,
        "created_at": (completed or T0) - timedelta(hours=1),
    }


def _finding_row(tid: uuid.UUID, sid: uuid.UUID, fp: str, severity: str, title: str) -> dict:
    return {
        "finding_id": str(uuid.uuid4()),
        "scan_id": str(sid),
        "title": title,
        "severity": severity,
        "created_at": T1,
    }


class _World:
    """Canned posture data: 2 active-adjacent targets, history, remediation."""

    def __init__(self) -> None:
        self.targets = [
            _target(T1_ID, "one.example"),
            _target(T2_ID, "two.example", archived=True),
            _target(T3_ID, "three.example"),
        ]
        self.scans = [
            _scan(S1_ID, T1_ID, "REPORT_READY", T1),
            _scan(S2_ID, T1_ID, "REPORT_READY", T2),
            _scan(S3_ID, T2_ID, "REPORT_READY", T1),
        ]
        self.lifecycle = {
            (str(T1_ID), "fp-a"): {
                "status": "PERSISTENT",
                "effective_at": T2,
                "observed_in_scan_id": str(S2_ID),
            },
            (str(T1_ID), "fp-b"): {
                "status": "RESOLVED",
                "effective_at": T2,
                "observed_in_scan_id": str(S2_ID),
            },
            (str(T1_ID), "fp-c"): {
                "status": "NEW",
                "effective_at": T2,
                "observed_in_scan_id": str(S2_ID),
            },
            (str(T1_ID), "fp-e"): {
                "status": "REGRESSED",
                "effective_at": T2,
                "observed_in_scan_id": str(S2_ID),
            },
            (str(T2_ID), "fp-d"): {
                "status": "PERSISTENT",
                "effective_at": T1,
                "observed_in_scan_id": str(S3_ID),
            },
        }
        self.findings = {
            (str(T1_ID), "fp-a"): _finding_row(T1_ID, S2_ID, "fp-a", "HIGH", "A worse"),
            (str(T1_ID), "fp-b"): _finding_row(T1_ID, S1_ID, "fp-b", "LOW", "B gone"),
            (str(T1_ID), "fp-c"): _finding_row(T1_ID, S2_ID, "fp-c", "CRITICAL", "C new"),
            (str(T1_ID), "fp-e"): _finding_row(T1_ID, S2_ID, "fp-e", "MEDIUM", "E back"),
            (str(T2_ID), "fp-d"): _finding_row(T2_ID, S3_ID, "fp-d", "MEDIUM", "D old"),
        }
        self.by_scan = {
            str(S1_ID): [
                {
                    "finding_id": "x",
                    "fingerprint": "fp-a",
                    "title": "A",
                    "severity": "MEDIUM",
                    "created_at": T1,
                },
                {
                    "finding_id": "y",
                    "fingerprint": "fp-b",
                    "title": "B",
                    "severity": "LOW",
                    "created_at": T1,
                },
            ],
            str(S2_ID): [
                {
                    "finding_id": "x",
                    "fingerprint": "fp-a",
                    "title": "A",
                    "severity": "HIGH",
                    "created_at": T2,
                },
                {
                    "finding_id": "y",
                    "fingerprint": "fp-c",
                    "title": "C",
                    "severity": "CRITICAL",
                    "created_at": T2,
                },
                {
                    "finding_id": "z",
                    "fingerprint": "fp-e",
                    "title": "E",
                    "severity": "MEDIUM",
                    "created_at": T2,
                },
            ],
            str(S3_ID): [
                {
                    "finding_id": "w",
                    "fingerprint": "fp-d",
                    "title": "D",
                    "severity": "MEDIUM",
                    "created_at": T1,
                },
            ],
        }
        self.scan_lifecycle = {
            str(S1_ID): {"fp-a": "NEW", "fp-b": "NEW"},
            str(S2_ID): {"fp-a": "PERSISTENT", "fp-c": "NEW", "fp-e": "REGRESSED"},
            str(S3_ID): {"fp-d": "PERSISTENT"},
        }
        self.remediation = {
            (str(T1_ID), "fp-a"): {"status": "DONE", "updated_at": T2},
            (str(T1_ID), "fp-c"): {"status": "TODO", "updated_at": T2},
        }
        self.enrichment = {
            (str(T1_ID), "fp-a"): [
                {
                    "source": "curated",
                    "external_ref": "CVE-2021-44228",
                    "cve_id": "CVE-2021-44228",
                    "cwe_id": None,
                    "cvss_score": 9.8,
                    "affected_technology": "nginx server",
                    "created_at": T1_5,
                },
            ],
        }
        self.technologies = {
            str(T1_ID): [
                {
                    "slug": "nginx",
                    "display": "nginx",
                    "family": "server",
                    "version": "1.25",
                    "confidence": "HIGH",
                    "first_observed_at": T0,
                    "last_observed_at": T2,
                },
            ],
        }
        self.events = [
            {
                "target_id": str(T1_ID),
                "fingerprint": "fp-b",
                "status": "NEW",
                "effective_at": T0,
                "observed_in_scan_id": str(S1_ID),
            },
            {
                "target_id": str(T1_ID),
                "fingerprint": "fp-b",
                "status": "RESOLVED",
                "effective_at": T0 + timedelta(hours=30),
                "observed_in_scan_id": str(S2_ID),
            },
            {
                "target_id": str(T1_ID),
                "fingerprint": "fp-x",
                "status": "NEW",
                "effective_at": T0,
                "observed_in_scan_id": str(S1_ID),
            },
            {
                "target_id": str(T1_ID),
                "fingerprint": "fp-e",
                "status": "NEW",
                "effective_at": T0,
                "observed_in_scan_id": str(S1_ID),
            },
            {
                "target_id": str(T1_ID),
                "fingerprint": "fp-e",
                "status": "RESOLVED",
                "effective_at": T1_5,
                "observed_in_scan_id": str(S1_ID),
            },
        ]
        self.calls: dict[str, int] = {}

    def _count(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    @staticmethod
    def _wanted(ids: list) -> set[str]:
        return {str(i) for i in ids}

    async def list_owned_targets(self, user_id: uuid.UUID) -> list[dict]:
        self._count("list_owned_targets")
        assert user_id == OWNER
        return list(self.targets)

    async def list_scans_for_user(self, user_id: uuid.UUID, *, limit: int) -> list[dict]:
        self._count("list_scans_for_user")
        assert user_id == OWNER
        return list(self.scans)[:limit]

    async def count_scans_for_user(self, user_id: uuid.UUID) -> dict:
        self._count("count_scans_for_user")
        assert user_id == OWNER
        return {
            "total": len(self.scans),
            "completed": sum(1 for s in self.scans if s["completed_at"] is not None),
        }

    async def latest_lifecycle_map(self, target_ids: list) -> dict:
        self._count("latest_lifecycle_map")
        wanted = self._wanted(target_ids)
        return {k: v for k, v in self.lifecycle.items() if k[0] in wanted}

    async def latest_findings_map(self, _user_id: uuid.UUID, target_ids: list) -> dict:
        self._count("latest_findings_map")
        wanted = self._wanted(target_ids)
        return {k: v for k, v in self.findings.items() if k[0] in wanted}

    async def findings_by_scan(self, _user_id: uuid.UUID, scan_ids: list) -> dict:
        self._count("findings_by_scan")
        wanted = {str(sid) for sid in scan_ids}
        return {sid: list(rows) for sid, rows in self.by_scan.items() if sid in wanted}

    async def history_events(self, target_ids: list, *, limit: int = 10_000) -> list[dict]:
        self._count("history_events")
        wanted = self._wanted(target_ids)
        return [e for e in self.events if e["target_id"] in wanted][:limit]

    async def remediation_map(self, target_ids: list) -> dict:
        self._count("remediation_map")
        wanted = self._wanted(target_ids)
        return {k: v for k, v in self.remediation.items() if k[0] in wanted}

    async def technologies_map(self, target_ids: list) -> dict:
        self._count("technologies_map")
        wanted = self._wanted(target_ids)
        return {tid: list(rows) for tid, rows in self.technologies.items() if tid in wanted}

    async def enrichment_map(self, target_ids: list) -> dict:
        self._count("enrichment_map")
        wanted = self._wanted(target_ids)
        return {k: v for k, v in self.enrichment.items() if k[0] in wanted}

    async def lifecycle_for_scans(self, scan_ids: list) -> dict:
        self._count("lifecycle_for_scans")
        return {str(sid): dict(self.scan_lifecycle.get(str(sid), {})) for sid in scan_ids}


def _service(monkeypatch: pytest.MonkeyPatch, world: _World) -> PostureService:
    from src.domain.posture.posture_service import PostureService
    from src.infrastructure.database.repositories.posture_repository import (
        PostureRepository,
    )

    for name in (
        "list_owned_targets",
        "list_scans_for_user",
        "count_scans_for_user",
        "latest_lifecycle_map",
        "latest_findings_map",
        "findings_by_scan",
        "history_events",
        "remediation_map",
        "technologies_map",
        "enrichment_map",
        "lifecycle_for_scans",
    ):
        monkeypatch.setattr(PostureRepository, name, getattr(world, name))
    return PostureService(object(), _principal(OWNER))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Posture snapshot                                                            #
# --------------------------------------------------------------------------- #


async def test_empty_account_returns_honest_zeros(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _World()
    world.targets = []
    world.scans = []
    world.lifecycle = {}
    world.findings = {}
    world.events = []
    service = _service(monkeypatch, world)
    posture = await service.get_posture()
    assert posture["targets_total"] == 0
    assert posture["open_findings_total"] == 0
    assert posture["severity_counts"] == {}
    assert posture["top_findings"] == []
    assert posture["regressions_total"] == 0
    assert posture["mttr"] is None
    assert posture["latest_scan"] is None
    assert posture["done_open_count"] == 0


async def test_target_and_scan_totals(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["targets_total"] == 3
    assert posture["targets_active"] == 2
    assert posture["scans_total"] == 3
    assert posture["scans_completed"] == 3
    assert posture["scans_in_flight"] == 0


async def test_severity_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["open_findings_total"] == 4
    assert posture["severity_counts"] == {"HIGH": 1, "CRITICAL": 1, "MEDIUM": 2}


async def test_priority_counts_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    # fp-a: HIGH+regressed? no: PERSISTENT, prev MEDIUM→HIGH(+15), CVE+5,
    #   CVSS 9.8+10, tech nginx+5 = 95 P1.
    # fp-c: CRITICAL new = 80 P1. fp-e: MEDIUM REGRESSED = 55 P2.
    # fp-d: MEDIUM = 40 P3.
    assert posture["priority_counts"] == {"P1": 2, "P2": 1, "P3": 1}
    assert posture["priority_version"] == "sgpt.priority.v2"
    assert all(f["priority"]["version"] == "sgpt.priority.v2" for f in posture["top_findings"])


async def test_lifecycle_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["lifecycle_counts"] == {"PERSISTENT": 2, "NEW": 1, "REGRESSED": 1}


async def test_remediation_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["remediation_counts"] == {"DONE": 1, "TODO": 1}
    assert posture["remediation_open_total"] == 2


async def test_done_open_gap_surfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    """DONE remediation on a still-PERSISTENT finding is listed, not hidden."""
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["done_open_count"] == 1
    (item,) = posture["done_open_items"]
    assert item["fingerprint"] == "fp-a"
    assert item["priority"]["level"] == "P1"


async def test_regression_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["regressions_total"] == 1
    assert posture["regressions_targets"] == [str(T1_ID)]
    (top,) = posture["top_regressions"]
    assert top["fingerprint"] == "fp-e"
    assert top["priority"]["score"] == 55


async def test_top_findings_ranked_deterministically(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    first = await service.get_posture()
    second = await service.get_posture()
    assert first == second
    scores = [f["priority"]["score"] for f in first["top_findings"]]
    assert scores == sorted(scores, reverse=True)
    assert [f["fingerprint"] for f in first["top_findings"]][0] == "fp-a"


async def test_latest_scan_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert posture["latest_scan"]["scan_id"] == str(S2_ID)
    assert posture["latest_scan"]["target_id"] == str(T1_ID)


async def test_mttr_with_valid_timestamps(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    mttr = posture["mttr"]
    assert mttr is not None
    # fp-b: 30h; fp-e: T0 → T1_5 = 1080h. Mean/median of both.
    assert mttr["mean_hours"] == 555.0
    assert mttr["median_hours"] == 555.0
    assert mttr["sample_size"] == 2
    assert mttr["resolved_identities"] == 2


async def test_mttr_empty_without_resolutions(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _World()
    world.events = [e for e in world.events if e["status"] != "RESOLVED"]
    service = _service(monkeypatch, world)
    posture = await service.get_posture()
    assert posture["mttr"] is None


async def test_no_organizations_leakage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Top-level keys are exactly the user-scoped contract (no org surface)."""
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    assert set(posture) == {
        "targets_total",
        "targets_active",
        "scans_total",
        "scans_completed",
        "scans_in_flight",
        "open_findings_total",
        "unresolved_identities",
        "severity_counts",
        "priority_counts",
        "lifecycle_counts",
        "remediation_counts",
        "remediation_open_total",
        "done_open_count",
        "done_open_items",
        "regressions_total",
        "regressions_targets",
        "top_regressions",
        "top_findings",
        "mttr",
        "latest_scan",
        "priority_version",
    }
    serialized = str(posture).lower()
    assert "organization" not in serialized


# --------------------------------------------------------------------------- #
# Target posture                                                              #
# --------------------------------------------------------------------------- #


async def test_target_cards(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    result = await service.get_targets_posture(limit=50)
    assert result["total"] == 3
    # Most-recently-scanned first; never-scanned last.
    assert [c["target_id"] for c in result["targets"]] == [str(T1_ID), str(T2_ID), str(T3_ID)]
    t1, t2, t3 = result["targets"]
    assert t1["open_findings_total"] == 3
    assert t1["severity_counts"] == {"HIGH": 1, "CRITICAL": 1, "MEDIUM": 1}
    assert t1["regressions_count"] == 1
    assert t1["previous_scan_id"] == str(S1_ID)
    assert t1["latest_scan"]["scan_id"] == str(S2_ID)
    assert t1["remediation_counts"] == {"DONE": 1, "TODO": 1}
    assert t1["done_open_count"] == 1
    assert t2["open_findings_total"] == 1
    assert t2["latest_scan"]["scan_id"] == str(S3_ID)
    assert t3["open_findings_total"] == 0
    assert t3["latest_scan"] is None
    assert t3["last_scan_at"] is None


# --------------------------------------------------------------------------- #
# Trends                                                                      #
# --------------------------------------------------------------------------- #


async def test_trend_insufficient_history(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _World()
    world.scans = [s for s in world.scans if s["id"] == str(S3_ID)]
    service = _service(monkeypatch, world)
    trends = await service.get_trends(target_id=None, limit=20)
    assert len(trends["points"]) == 1
    assert trends["insufficient_history"] is True


async def test_trend_multiple_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    trends = await service.get_trends(target_id=T1_ID, limit=20)
    assert trends["insufficient_history"] is False
    assert [p["scan_id"] for p in trends["points"]] == [str(S1_ID), str(S2_ID)]
    first, second = trends["points"]
    assert first["total_findings"] == 2
    assert second["total_findings"] == 3
    assert second["new_count"] == 1  # fp-c (fp-e is a regression)
    assert second["resolved_count"] == 1  # fp-b
    assert second["regressed_count"] == 1  # fp-e
    assert first["new_count"] == 2
    assert first["resolved_count"] == 0


async def test_trend_new_vs_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    trends = await service.get_trends(target_id=T1_ID, limit=20)
    assert trends["points"][0]["severity_counts"] == {"MEDIUM": 1, "LOW": 1}
    assert trends["points"][1]["severity_counts"] == {"HIGH": 1, "CRITICAL": 1, "MEDIUM": 1}


async def test_trend_priority_distribution(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    trends = await service.get_trends(target_id=T1_ID, limit=20)
    first, second = trends["points"]
    # Point 1 (pre-enrichment): MEDIUM NEW=40 P3, LOW NEW=20 P4.
    assert first["priority_counts"] == {"P3": 1, "P4": 1}
    # Point 2: fp-a P1 (95), fp-c P1 (80), fp-e P2 (55).
    assert second["priority_counts"] == {"P1": 2, "P2": 1}
    assert trends["priority_version"] == "sgpt.priority.v2"


async def test_trend_has_no_remediation_series(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remediation has no per-scan history: points carry none (documented)."""
    service = _service(monkeypatch, _World())
    trends = await service.get_trends(target_id=T1_ID, limit=20)
    for point in trends["points"]:
        assert set(point) == {
            "scan_id",
            "target_id",
            "completed_at",
            "status",
            "total_findings",
            "severity_counts",
            "priority_counts",
            "new_count",
            "resolved_count",
            "regressed_count",
        }


async def test_trend_unknown_target_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _World())
    with pytest.raises(NotFoundError):
        await service.get_trends(target_id=uuid.uuid4(), limit=20)


# --------------------------------------------------------------------------- #
# Isolation, determinism, query discipline                                    #
# --------------------------------------------------------------------------- #


async def test_cross_owner_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    _service(monkeypatch, _World())
    intruder = PostureService(object(), _principal(uuid.uuid4()))  # type: ignore[arg-type]
    # The fakes assert the owner's id on every call; an intruder principal
    # would fail those assertions (proving user scoping flows through).
    with pytest.raises(AssertionError):
        await intruder.get_posture()


async def test_no_n_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """Call counts stay constant when targets are added (batched queries).

    Adding empty targets must not add repository calls: every method is
    called a fixed number of times however many targets exist.
    """
    from src.infrastructure.database.repositories.posture_repository import (
        PostureRepository,
    )

    methods = (
        "list_owned_targets",
        "list_scans_for_user",
        "count_scans_for_user",
        "latest_lifecycle_map",
        "latest_findings_map",
        "findings_by_scan",
        "history_events",
        "remediation_map",
        "technologies_map",
        "enrichment_map",
        "lifecycle_for_scans",
    )

    async def snapshot(n_extra: int) -> dict[str, int]:
        world = _World()
        for i in range(n_extra):
            tid = uuid.uuid4()
            world.targets.append(
                {
                    "id": str(tid),
                    "hostname": f"extra{i}.example",
                    "normalized_url": f"https://extra{i}.example/",
                    "is_archived": False,
                    "created_at": T0,
                }
            )
        for name in methods:
            monkeypatch.setattr(PostureRepository, name, getattr(world, name))
        from src.domain.posture.posture_service import PostureService as _Svc

        service = _Svc(object(), _principal(OWNER))  # type: ignore[arg-type]
        await service.get_posture()
        return dict(world.calls)

    base = await snapshot(0)
    grown = await snapshot(3)
    assert base == grown, f"call counts grew with targets: {base} vs {grown}"


async def test_report_compatibility(monkeypatch: pytest.MonkeyPatch) -> None:
    """Posture snapshots share the reporter's v2 shape (score/level/version)."""
    service = _service(monkeypatch, _World())
    posture = await service.get_posture()
    for finding in posture["top_findings"]:
        snapshot = finding["priority"]
        assert set(snapshot) == {"score", "level", "version", "factors"}
        assert snapshot["version"] == "sgpt.priority.v2"


# --------------------------------------------------------------------------- #
# Routes                                                                      #
# --------------------------------------------------------------------------- #


@pytest.fixture
def posture_client(monkeypatch: pytest.MonkeyPatch):
    from src.api.dependencies import get_current_user, get_db_session
    from src.infrastructure.database.repositories.posture_repository import (
        PostureRepository,
    )
    from src.main import create_application

    world = _World()
    for name in (
        "list_owned_targets",
        "list_scans_for_user",
        "count_scans_for_user",
        "latest_lifecycle_map",
        "latest_findings_map",
        "findings_by_scan",
        "history_events",
        "remediation_map",
        "technologies_map",
        "enrichment_map",
        "lifecycle_for_scans",
    ):
        monkeypatch.setattr(PostureRepository, name, getattr(world, name))

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield object()

    application = create_application()
    application.dependency_overrides[get_current_user] = lambda: _principal(OWNER)
    application.dependency_overrides[get_db_session] = _overridden_session
    return TestClient(application)


def test_routes_return_shaped_dtos(posture_client: TestClient) -> None:
    posture = posture_client.get("/api/v1/dashboard/posture")
    assert posture.status_code == 200, posture.text
    body = posture.json()
    assert body["openFindingsTotal"] == 4
    assert body["priorityVersion"] == "sgpt.priority.v2"
    assert body["mttr"]["sampleSize"] == 2

    trends = posture_client.get("/api/v1/dashboard/trends?limit=20")
    assert trends.status_code == 200, trends.text
    assert trends.json()["insufficientHistory"] is False

    targets = posture_client.get("/api/v1/dashboard/targets")
    assert targets.status_code == 200, targets.text
    assert targets.json()["total"] == 3

    filtered = posture_client.get(f"/api/v1/dashboard/trends?targetId={T1_ID}")
    assert filtered.status_code == 200
    assert {p["scanId"] for p in filtered.json()["points"]} == {str(S1_ID), str(S2_ID)}

    unknown = posture_client.get(f"/api/v1/dashboard/trends?targetId={uuid.uuid4()}")
    assert unknown.status_code == 404

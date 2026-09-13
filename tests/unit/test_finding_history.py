"""Per-finding history endpoint (fingerprint identity, no invented events).

Service-level proofs with patched repository seams plus HTTP envelope
proofs (tenant gate, association check, camelCase contract).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.domain.errors import NotFoundError
from src.domain.scans.scan_service import ScanService
from tests.unit.conftest import _principal  # noqa: F401 — shared harness

SCAN_A = uuid.uuid4()
SCAN_B = uuid.uuid4()
SCAN_FOREIGN = uuid.uuid4()
TARGET = uuid.uuid4()
FP = "fp-history-aaa"
FID_A = uuid.uuid4()
FID_B = uuid.uuid4()


def _row(fid: uuid.UUID, scan_id: uuid.UUID, severity_id: int = 3) -> object:
    return type(
        "F",
        (),
        {
            "id": fid,
            "scan_id": scan_id,
            "title": "Missing HSTS",
            "fingerprint": FP,
            "severity_id": severity_id,
        },
    )()


def _patch_history_seams(
    monkeypatch: pytest.MonkeyPatch,
    *,
    visible_scan_ids: set[uuid.UUID] | None = None,
    finding_row: object | None = None,
    occurrences: list[dict[str, object]] | None = None,
    events: list[dict[str, object]] | None = None,
) -> None:
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    allowed = visible_scan_ids if visible_scan_ids is not None else {SCAN_A, SCAN_B}

    def _scan(scan_id: uuid.UUID) -> object:
        return type("S", (), {"id": scan_id, "target_id": TARGET})()

    async def _visible(self: object, _sid: uuid.UUID) -> object:
        if _sid in allowed:
            return _scan(_sid)
        raise NotFoundError()

    async def _finding(self: object, _fid: uuid.UUID) -> object | None:
        return finding_row

    async def _occurrences(self: object, **kwargs: object) -> list[dict[str, object]]:
        assert kwargs["fingerprint"] == FP
        assert kwargs["target_id"] == TARGET
        return list(occurrences or [])

    async def _events(self: object, **kwargs: object) -> list[dict[str, object]]:
        return list(events or [])

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", _finding)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_findings_by_fingerprint", _occurrences)
    monkeypatch.setattr(ScanEngineExecutionRepository, "lifecycle_events_for_fingerprint", _events)

    async def _severity(self: object, _finding: object) -> str:
        return "HIGH"

    monkeypatch.setattr(ScanService, "_finding_severity", _severity)


class _FakeSession:
    """Minimal session double: severity lookup only (history seams patched)."""

    async def execute(self, _stmt: object) -> object:
        return type("R", (), {"scalar": lambda _self: "HIGH"})()  # noqa: ARG005 - lambda receiver


def _service(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> ScanService:
    _patch_history_seams(monkeypatch, **kwargs)  # type: ignore[arg-type]
    return ScanService(_FakeSession(), _principal())  # type: ignore[arg-type]


def _occ(fid: uuid.UUID, scan_id: uuid.UUID, severity: str, day: int) -> dict[str, object]:
    return {
        "id": str(fid),
        "scan_id": str(scan_id),
        "title": "Missing HSTS",
        "severity": severity,
        "created_at": datetime(2026, 1, day, tzinfo=UTC),
    }


async def test_persistent_history_with_severity_change(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(
        monkeypatch,
        finding_row=_row(FID_B, SCAN_B),
        occurrences=[_occ(FID_A, SCAN_A, "MEDIUM", 1), _occ(FID_B, SCAN_B, "HIGH", 5)],
        events=[
            {
                "status": "NEW",
                "effective_at": datetime(2026, 1, 1, tzinfo=UTC),
                "observed_in_scan_id": str(SCAN_A),
            },
            {
                "status": "PERSISTENT",
                "effective_at": datetime(2026, 1, 5, tzinfo=UTC),
                "observed_in_scan_id": str(SCAN_B),
            },
        ],
    )
    history = await service.get_finding_history(SCAN_B, FID_B)
    assert history is not None
    assert history["fingerprint"] == FP
    assert history["current_severity"] == "HIGH"
    assert history["previous_severity"] == "MEDIUM"
    assert history["lifecycle_status"] == "PERSISTENT"
    assert history["first_seen_at"] == "2026-01-01T00:00:00+00:00"
    assert history["last_seen_at"] == "2026-01-05T00:00:00+00:00"
    assert len(history["occurrences"]) == 2  # type: ignore[arg-type]
    assert history["severity_changes"] == [  # type: ignore[comparison-overlap]
        {
            "from": "MEDIUM",
            "to": "HIGH",
            "scan_id": str(SCAN_B),
            "at": "2026-01-05T00:00:00+00:00",
        }
    ]


async def test_no_history_for_single_occurrence(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(
        monkeypatch, finding_row=_row(FID_A, SCAN_A), occurrences=[_occ(FID_A, SCAN_A, "HIGH", 1)]
    )
    history = await service.get_finding_history(SCAN_A, FID_A)
    assert history is not None
    assert history["previous_severity"] is None
    assert history["severity_changes"] == []
    assert history["lifecycle_status"] is None


async def test_finding_without_fingerprint_has_no_cross_scan_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _row(FID_A, SCAN_A)
    row.fingerprint = None  # type: ignore[attr-defined]
    service = _service(monkeypatch, finding_row=row)
    history = await service.get_finding_history(SCAN_A, FID_A)
    assert history is not None
    assert history["fingerprint"] is None
    assert history["occurrences"] == []


async def test_unknown_finding_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, finding_row=None)
    assert await service.get_finding_history(SCAN_A, uuid.uuid4()) is None


async def test_finding_from_another_scan_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, finding_row=_row(FID_A, SCAN_FOREIGN))
    assert await service.get_finding_history(SCAN_A, FID_A) is None


async def test_cross_tenant_scan_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, visible_scan_ids={SCAN_A}, finding_row=_row(FID_A, SCAN_A))
    # The tenant gate raises before any finding data is touched.
    with pytest.raises(NotFoundError):
        await service.get_finding_history(SCAN_FOREIGN, FID_A)


@pytest.fixture
def history_client(monkeypatch: pytest.MonkeyPatch):
    """App with history seams patched (finding lives in SCAN_A)."""
    from src.api.dependencies import get_current_user
    from src.main import create_application

    _patch_history_seams(
        monkeypatch,
        finding_row=_row(FID_A, SCAN_A),
        occurrences=[_occ(FID_A, SCAN_A, "HIGH", 1)],
    )
    app = create_application()
    app.dependency_overrides[get_current_user] = lambda: _principal()
    return TestClient(app)


def test_history_endpoint_contract(history_client: TestClient) -> None:
    response = history_client.get(f"/api/v1/scans/{SCAN_A}/findings/{FID_A}/history")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["findingId"] == str(FID_A)
    assert body["scanId"] == str(SCAN_A)
    assert body["fingerprint"] == FP
    assert body["currentSeverity"] == "HIGH"
    assert body["occurrences"][0]["findingId"] == str(FID_A)


def test_history_endpoint_cross_tenant_is_404(
    history_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.domain.scans.scan_service import ScanService as Service

    async def _deny(self: object, _sid: uuid.UUID) -> object:
        raise NotFoundError()

    monkeypatch.setattr(Service, "_get_visible_scan", _deny)
    response = history_client.get(f"/api/v1/scans/{SCAN_FOREIGN}/findings/{FID_A}/history")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"

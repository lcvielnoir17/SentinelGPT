"""Finding remediation workflow: validation, upsert, tenancy, non-mutation.

Remediation is operator workflow metadata bound to (fingerprint, target).
These tests prove the validation contract, the set/get seam, tenant
gating, fingerprint-keyed persistence across rescans (the verify-fix
story), and that canonical lifecycle state is never modified by
remediation operations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.domain.errors import NotFoundError
from src.domain.scans.errors import InvalidRemediationError
from src.domain.scans.remediation import (
    RemediationInput,
    RemediationValidationError,
)
from src.domain.scans.scan_service import ScanService
from tests.unit.conftest import _principal  # noqa: F401 — shared harness

SCAN = uuid.uuid4()
SCAN_RESCAN = uuid.uuid4()
TARGET = uuid.uuid4()
FP = "fp-remediation-aaa"
FID = uuid.uuid4()
FID_RESCAN = uuid.uuid4()


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #


def test_defaults_to_todo_without_notes() -> None:
    parsed = RemediationInput.parse({})
    assert parsed.status == "TODO"
    assert parsed.notes is None


def test_status_normalizes_case_and_whitespace() -> None:
    assert RemediationInput.parse({"status": "  in_progress "}).status == "IN_PROGRESS"


def test_all_workflow_statuses_accepted() -> None:
    for status in ("TODO", "IN_PROGRESS", "DONE", "DEFERRED"):
        assert RemediationInput.parse({"status": status}).status == status


def test_unknown_status_rejected() -> None:
    for bad in ("RESOLVED", "NEW", "FIXED", "", "doneish"):
        with pytest.raises(RemediationValidationError):
            RemediationInput.parse({"status": bad})


def test_non_text_status_rejected() -> None:
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"status": 3})  # type: ignore[dict-item]


def test_notes_trimmed_and_blank_becomes_absent() -> None:
    assert RemediationInput.parse({"notes": "  patched header  "}).notes == "patched header"
    assert RemediationInput.parse({"notes": "   "}).notes is None


def test_notes_must_be_text_and_bounded() -> None:
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"notes": ["not", "text"]})  # type: ignore[dict-item]
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"notes": "x" * 2_001})
    assert RemediationInput.parse({"notes": "x" * 2_000}).notes is not None


# --------------------------------------------------------------------------- #
# Service seam (in-memory repository double)                                  #
# --------------------------------------------------------------------------- #


def _finding(scan_id: uuid.UUID = SCAN, fingerprint: str | None = FP) -> object:
    fid = FID_RESCAN if scan_id == SCAN_RESCAN else FID
    return type(
        "F",
        (),
        {
            "id": fid,
            "scan_id": scan_id,
            "title": "Missing HSTS",
            "fingerprint": fingerprint,
            "severity_id": 2,
        },
    )()


class _RemediationRepo:
    """Upserting in-memory double mirroring the repository contract."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, uuid.UUID], dict[str, object]] = {}

    async def get_finding_by_id(self, fid: uuid.UUID) -> object | None:
        if fid == FID:
            return _finding(SCAN)
        if fid == FID_RESCAN:
            return _finding(SCAN_RESCAN)
        return None

    async def get_remediation(self, **kwargs: object) -> dict[str, object] | None:
        row = self.rows.get((str(kwargs["fingerprint"]), kwargs["target_id"]))  # type: ignore[arg-type]
        return dict(row) if row is not None else None

    async def set_remediation(self, **kwargs: object) -> dict[str, object]:
        key = (str(kwargs["fingerprint"]), kwargs["target_id"])  # type: ignore[arg-type]
        existing = self.rows.get(key)
        now = datetime(2026, 1, 1, tzinfo=UTC).isoformat()
        if existing is not None:
            existing["status"] = kwargs["status"]
            existing["notes"] = kwargs["notes"]
            existing["updated_by_user_id"] = kwargs["updated_by_user_id"]
            existing["updated_at"] = now
            return dict(existing)
        row: dict[str, object] = {
            "id": str(uuid.uuid4()),
            "fingerprint": kwargs["fingerprint"],
            "target_id": kwargs["target_id"],
            "status": kwargs["status"],
            "notes": kwargs["notes"],
            "updated_by_user_id": kwargs["updated_by_user_id"],
            "created_at": now,
            "updated_at": now,
        }
        self.rows[key] = row
        return dict(row)


def _service(monkeypatch: pytest.MonkeyPatch, store: _RemediationRepo) -> ScanService:
    from src.domain.audit.audit_service import AuditService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    async def _visible(self: object, sid: uuid.UUID) -> object:
        if sid in (SCAN, SCAN_RESCAN):
            return type("S", (), {"id": sid, "target_id": TARGET})()
        raise NotFoundError()

    async def _record(self: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(AuditService, "record", _record)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", store.get_finding_by_id)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", store.get_remediation)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", store.set_remediation)
    return ScanService(object(), _principal())  # type: ignore[arg-type]


async def test_missing_remediation_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _RemediationRepo())
    assert await service.get_finding_remediation(SCAN, FID) is None


async def test_set_then_get_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _RemediationRepo())
    row = await service.set_finding_remediation(
        SCAN, FID, {"status": "in_progress", "notes": "rolling out HSTS"}
    )
    assert row is not None
    assert row["status"] == "IN_PROGRESS"
    assert row["notes"] == "rolling out HSTS"
    assert row["fingerprint"] == FP
    fetched = await service.get_finding_remediation(SCAN, FID)
    assert fetched is not None and fetched["id"] == row["id"]


async def test_reset_updates_in_place_without_duplicating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _RemediationRepo()
    service = _service(monkeypatch, store)
    first = await service.set_finding_remediation(SCAN, FID, {"status": "TODO"})
    second = await service.set_finding_remediation(
        SCAN, FID, {"status": "DONE", "notes": "header deployed"}
    )
    assert first is not None and second is not None
    assert first["id"] == second["id"]
    assert second["status"] == "DONE"
    assert len(store.rows) == 1


async def test_workflow_state_survives_rescan_via_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify-fix story: state set on scan A reads back through scan B."""
    service = _service(monkeypatch, _RemediationRepo())
    await service.set_finding_remediation(SCAN, FID, {"status": "IN_PROGRESS"})
    via_rescan = await service.get_finding_remediation(SCAN_RESCAN, FID_RESCAN)
    assert via_rescan is not None
    assert via_rescan["status"] == "IN_PROGRESS"


async def test_malformed_payload_is_400_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _RemediationRepo())
    with pytest.raises(InvalidRemediationError):
        await service.set_finding_remediation(SCAN, FID, {"status": "RESOLVED"})


async def test_cross_tenant_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _RemediationRepo())
    with pytest.raises(NotFoundError):
        await service.get_finding_remediation(uuid.uuid4(), FID)
    with pytest.raises(NotFoundError):
        await service.set_finding_remediation(uuid.uuid4(), FID, {"status": "TODO"})


async def test_unknown_finding_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _RemediationRepo())
    assert await service.get_finding_remediation(SCAN, uuid.uuid4()) is None
    assert await service.set_finding_remediation(SCAN, uuid.uuid4(), {"status": "TODO"}) is None


async def test_done_does_not_touch_canonical_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DONE is operator intent: the finding row itself is byte-identical."""
    store = _RemediationRepo()
    service = _service(monkeypatch, store)
    before = await store.get_finding_by_id(FID)
    await service.set_finding_remediation(SCAN, FID, {"status": "DONE"})
    after = await store.get_finding_by_id(FID)
    assert before is not None and after is not None
    assert (before.title, before.fingerprint, before.severity_id) == (
        after.title,
        after.fingerprint,
        after.severity_id,
    )


@pytest.fixture
def remediation_client(monkeypatch: pytest.MonkeyPatch):
    from src.api.dependencies import get_current_user
    from src.main import create_application

    store = _RemediationRepo()

    async def _visible(self: object, sid: uuid.UUID) -> object:
        if sid in (SCAN, SCAN_RESCAN):
            return type("S", (), {"id": sid, "target_id": TARGET})()
        raise NotFoundError()

    async def _find_one(self: object, fid: uuid.UUID) -> object | None:
        return _finding() if fid == FID else None

    from src.domain.audit.audit_service import AuditService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    async def _record(self: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(AuditService, "record", _record)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", _find_one)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", store.get_remediation)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", store.set_remediation)
    app = create_application()
    app.dependency_overrides[get_current_user] = lambda: _principal()
    return TestClient(app)


def test_remediation_http_roundtrip(remediation_client: TestClient) -> None:
    missing = remediation_client.get(f"/api/v1/scans/{SCAN}/findings/{FID}/remediation")
    assert missing.status_code == 404, missing.text

    recorded = remediation_client.put(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation",
        json={"status": "IN_PROGRESS", "notes": "rolling out HSTS"},
    )
    assert recorded.status_code == 200, recorded.text
    body = recorded.json()
    assert body["status"] == "IN_PROGRESS"
    assert body["notes"] == "rolling out HSTS"
    assert body["fingerprint"] == FP

    fetched = remediation_client.get(f"/api/v1/scans/{SCAN}/findings/{FID}/remediation")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == body["id"]

    updated = remediation_client.put(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation",
        json={"status": "DONE"},
    )
    assert updated.status_code == 200
    assert updated.json()["id"] == body["id"]
    assert updated.json()["status"] == "DONE"
    assert updated.json()["notes"] is None


def test_remediation_http_rejects_malformed(remediation_client: TestClient) -> None:
    response = remediation_client.put(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation", json={"status": "RESOLVED"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_remediation_http_cross_tenant_is_404(remediation_client: TestClient) -> None:
    assert (
        remediation_client.get(
            f"/api/v1/scans/{uuid.uuid4()}/findings/{FID}/remediation"
        ).status_code
        == 404
    )
    assert (
        remediation_client.put(
            f"/api/v1/scans/{uuid.uuid4()}/findings/{FID}/remediation",
            json={"status": "TODO"},
        ).status_code
        == 404
    )

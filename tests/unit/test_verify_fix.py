"""Verify-fix workflow: rescan linkage, derived status, audit history.

Requesting verification creates a normal rescan (all gates enforced)
and links it; status derives live from the rescan (pending / stale /
verified_fixed / still_present) and is never stored. Remediation writes
and verify requests append audit rows (the remediation timeline).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import get_settings
from src.domain.errors import NotFoundError
from src.domain.users.token_service import create_access_token
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import User
from src.main import create_application

SETTINGS = get_settings()
NOW = datetime.now(UTC)

SCAN_A = uuid.uuid4()
SCAN_B = uuid.uuid4()
FID = uuid.uuid4()
FP = "fp-verify-aaa"


def _user() -> User:
    now = datetime.now(UTC)
    return User(
        id=uuid.uuid4(),
        email="owner@example.com",
        password_hash="x",
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


class _ScanRow:
    def __init__(self, sid: uuid.UUID, status: str, completed: datetime | None = None) -> None:
        self.id = sid
        self.target_id = uuid.uuid4()
        self.status_code = status
        self.completed_at = completed
        self.initiated_by_user_id = uuid.uuid4()


def _service(monkeypatch: pytest.MonkeyPatch, store: dict, principal) -> object:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        current = store.get("scans", {})
        if sid in current:
            return current[sid]
        raise NotFoundError()

    async def fake_finding(_self: object, fid: uuid.UUID) -> object:
        if fid != FID:
            return None
        return type("F", (), {"id": fid, "scan_id": SCAN_A, "fingerprint": FP})()

    async def fake_in_scan(_self: object, _sid: uuid.UUID, _fid: uuid.UUID) -> bool:
        return True

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", fake_finding)
    monkeypatch.setattr(ScanService, "_finding_in_scan", fake_in_scan)
    return ScanService(object(), principal)  # type: ignore[arg-type]


def _remediation_double(monkeypatch, store: dict):  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    async def fake_get(_self: object, **kwargs: object):
        return store.get("remediation")

    async def fake_set(_self: object, **kwargs: object) -> dict:
        row = {"status": kwargs["status"], "fingerprint": kwargs["fingerprint"]}
        store["remediation"] = row
        return dict(row)

    async def fake_link(_self: object, **kwargs: object) -> dict:
        store["linked_scan"] = kwargs["scan_id"]
        return {"linked": True}

    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", fake_get)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", fake_set)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_verification_link", fake_link)


# --------------------------------------------------------------------------- #
# Request                                                                     #
# --------------------------------------------------------------------------- #


async def test_request_creates_rescan_and_links(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    store: dict = {}
    service = _service(monkeypatch, store, principal)
    service_scan = _ScanRow(SCAN_A, "REPORT_READY", NOW)
    store["scans"] = {SCAN_A: service_scan}
    _remediation_double(monkeypatch, store)
    store["remediation"] = {"status": "IN_PROGRESS"}

    async def fake_rescan(_self: object, _sid: uuid.UUID) -> object:
        return type("R", (), {"id": SCAN_B, "status_code": "QUEUED"})()

    monkeypatch.setattr(ScanService, "rescan_scan", fake_rescan)

    audits: list = []

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(kwargs)

    from src.domain.audit.audit_service import AuditService

    monkeypatch.setattr(AuditService, "record", fake_record)

    outcome = await service.request_verify_fix(SCAN_A, FID)
    assert outcome is not None
    assert outcome["state"] == "pending"
    assert outcome["rescan_id"] == str(SCAN_B)
    assert store["linked_scan"] == SCAN_B
    assert any(a["action_code"] == "REMEDIATION_VERIFY_REQUESTED" for a in audits)


async def test_request_requires_remediation_state(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    store: dict = {}
    service = _service(monkeypatch, store, principal)
    service_scan = _ScanRow(SCAN_A, "REPORT_READY", NOW)
    store["scans"] = {SCAN_A: service_scan}
    _remediation_double(monkeypatch, store)

    # No remediation row seeded.
    async def fake_rescan(_self: object, _sid: uuid.UUID) -> object:  # type: ignore[no-untyped-def]
        raise AssertionError("rescan must not run without workflow state")

    monkeypatch.setattr(ScanService, "rescan_scan", fake_rescan)
    with pytest.raises(NotFoundError):
        await service.request_verify_fix(SCAN_A, FID)


async def test_request_unknown_finding_is_not_found(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    store: dict = {}
    service = _service(monkeypatch, store, principal)
    with pytest.raises(NotFoundError):
        await service.request_verify_fix(SCAN_A, uuid.uuid4())


async def test_request_propagates_rate_limit(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.errors import ScanRateLimitedError
    from src.domain.scans.scan_service import ScanService

    store: dict = {}
    service = _service(monkeypatch, store, principal)
    store["scans"] = {SCAN_A: _ScanRow(SCAN_A, "REPORT_READY", NOW)}
    _remediation_double(monkeypatch, store)
    store["remediation"] = {"status": "IN_PROGRESS"}

    async def fake_limited(_self: object, _sid: uuid.UUID) -> object:
        raise ScanRateLimitedError()

    monkeypatch.setattr(ScanService, "rescan_scan", fake_limited)
    with pytest.raises(ScanRateLimitedError):
        await service.request_verify_fix(SCAN_A, FID)
    assert "linked_scan" not in store  # nothing persisted on gate failure


# --------------------------------------------------------------------------- #
# Status (derived, never stored)                                              #
# --------------------------------------------------------------------------- #


def _status_service(monkeypatch, principal, rescan_status: str, present: bool):  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    store: dict = {}
    service = _service(monkeypatch, store, principal)
    store["scans"] = {
        SCAN_A: _ScanRow(SCAN_A, "REPORT_READY", NOW),
        SCAN_B: _ScanRow(SCAN_B, rescan_status, NOW if "READY" in rescan_status else None),
    }
    _remediation_double(monkeypatch, store)
    store["remediation"] = {"status": "DONE", "verified_in_scan_id": str(SCAN_B)}

    async def fake_compare(_self: object, _a: uuid.UUID, _b: uuid.UUID) -> dict:
        resolved = [] if present else [{"fingerprint": FP}]
        current = [{"fingerprint": FP}] if present else []
        return {"resolved": resolved, "new": current, "persistent": [], "regressed": []}

    monkeypatch.setattr(ScanService, "compare_scans", fake_compare)
    return service


async def test_status_verified_fixed(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    service = _status_service(monkeypatch, principal, "REPORT_READY", present=False)
    status = await service.get_verify_fix_status(SCAN_A, FID)
    assert status is not None
    assert status["state"] == "verified_fixed"
    assert status["rescan_id"] == str(SCAN_B)


async def test_status_still_present(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    service = _status_service(monkeypatch, principal, "REPORT_READY", present=True)
    status = await service.get_verify_fix_status(SCAN_A, FID)
    assert status is not None
    assert status["state"] == "still_present"


async def test_status_pending_while_running(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    service = _status_service(monkeypatch, principal, "RUNNING", present=True)
    status = await service.get_verify_fix_status(SCAN_A, FID)
    assert status is not None
    assert status["state"] == "pending"


async def test_status_stale_on_rejected_rescan(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    service = _status_service(monkeypatch, principal, "REJECTED", present=True)
    status = await service.get_verify_fix_status(SCAN_A, FID)
    assert status is not None
    assert status["state"] == "stale"


async def test_status_none_without_link(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    store: dict = {}
    service = _service(monkeypatch, store, principal)
    store["scans"] = {SCAN_A: _ScanRow(SCAN_A, "REPORT_READY", NOW)}
    _remediation_double(monkeypatch, store)

    async def fake_empty(_self: object, **kwargs: object):
        return None

    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", fake_empty)
    status = await service.get_verify_fix_status(SCAN_A, FID)
    assert status is not None and status["state"] == "none"


async def test_repeated_verification_relinks(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    store: dict = {}
    service = _service(monkeypatch, store, principal)
    store["scans"] = {SCAN_A: _ScanRow(SCAN_A, "REPORT_READY", NOW)}
    _remediation_double(monkeypatch, store)
    store["remediation"] = {"status": "DONE"}

    made: list = []

    async def fake_rescan(_self: object, _sid: uuid.UUID) -> object:
        new_id = uuid.uuid4()
        made.append(new_id)
        return type("R", (), {"id": new_id, "status_code": "QUEUED"})()

    monkeypatch.setattr(ScanService, "rescan_scan", fake_rescan)

    from src.domain.audit.audit_service import AuditService

    audits: list = []

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(kwargs)

    monkeypatch.setattr(AuditService, "record", fake_record)
    first = await service.request_verify_fix(SCAN_A, FID)
    second = await service.request_verify_fix(SCAN_A, FID)
    assert first is not None and second is not None
    assert first["rescan_id"] != second["rescan_id"]
    assert store["linked_scan"] == uuid.UUID(second["rescan_id"])
    assert sum(1 for a in audits if a["action_code"] == "REMEDIATION_VERIFY_REQUESTED") == 2


# --------------------------------------------------------------------------- #
# Remediation audit timeline                                                  #
# --------------------------------------------------------------------------- #


async def test_remediation_writes_audit_history(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    store: dict = {}
    service = _service(monkeypatch, store, principal)
    store["scans"] = {SCAN_A: _ScanRow(SCAN_A, "REPORT_READY", NOW)}
    _remediation_double(monkeypatch, store)

    audits: list = []

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(kwargs)

    from src.domain.audit.audit_service import AuditService

    monkeypatch.setattr(AuditService, "record", fake_record)
    await service.set_finding_remediation(SCAN_A, FID, {"status": "IN_PROGRESS"})
    await service.set_finding_remediation(SCAN_A, FID, {"status": "DONE"})
    updates = [a for a in audits if a["action_code"] == "REMEDIATION_UPDATED"]
    assert len(updates) == 2
    assert updates[0]["metadata_json"]["to"] == "IN_PROGRESS"
    assert updates[1]["metadata_json"]["to"] == "DONE"


# --------------------------------------------------------------------------- #
# HTTP envelope                                                               #
# --------------------------------------------------------------------------- #


@pytest.fixture
def principal() -> User:
    return _user()


@pytest.fixture
async def client(monkeypatch, principal):  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.user_repository import UserRepository

    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield object()

    application.dependency_overrides[get_db_session] = _overridden_session

    async def fake_get_by_user_id(_self: object, user_id: uuid.UUID):  # type: ignore[no-untyped-def]
        return principal if user_id == principal.id else None

    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_user_id)
    transport = ASGITransport(app=application)
    return AsyncClient(transport=transport, base_url="http://test")


def _auth_cookies(user: User) -> dict[str, str]:
    token = create_access_token(
        user_id=user.id,
        secret_key=SETTINGS.jwt_secret_key,
        algorithm=SETTINGS.jwt_algorithm,
        expires_in_minutes=SETTINGS.access_token_expire_minutes,
    )
    return {"accessToken": token}


async def test_route_verify_fix_roundtrip(client: AsyncClient, principal, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        rows = {
            SCAN_A: _ScanRow(SCAN_A, "REPORT_READY", NOW),
            SCAN_B: _ScanRow(SCAN_B, "REPORT_READY", NOW),
        }
        if sid in rows:
            return rows[sid]
        raise NotFoundError()

    async def fake_finding(_self: object, fid: uuid.UUID) -> object:
        return type("F", (), {"id": fid, "scan_id": SCAN_A, "fingerprint": FP})()

    async def fake_get(_self: object, **kwargs: object):
        return {"status": "DONE", "verified_in_scan_id": str(SCAN_B)}

    async def fake_set(_self: object, **kwargs: object) -> dict:
        return {"status": kwargs["status"]}

    async def fake_link(_self: object, **kwargs: object) -> dict:
        return {"linked": True}

    async def fake_rescan(_self: object, _sid: uuid.UUID) -> object:
        return type("R", (), {"id": SCAN_B, "status_code": "QUEUED"})()

    async def fake_compare(_self: object, _a: uuid.UUID, _b: uuid.UUID) -> dict:
        return {"resolved": [{"fingerprint": FP}], "new": [], "persistent": [], "regressed": []}

    async def fake_status(_self: object, scan: object) -> str:
        return scan.status_code

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", fake_finding)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", fake_get)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", fake_set)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_verification_link", fake_link)
    monkeypatch.setattr(ScanService, "rescan_scan", fake_rescan)
    monkeypatch.setattr(ScanService, "compare_scans", fake_compare)
    monkeypatch.setattr(ScanService, "_status_for_scan", fake_status)

    from src.domain.audit.audit_service import AuditService

    async def fake_audit_record(_self: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(AuditService, "record", fake_audit_record)

    import src.workers.scan_tasks as scan_tasks

    monkeypatch.setattr(scan_tasks, "enqueue_scan", lambda _scan_id: "task-verify-1")

    requested = await client.post(
        f"/api/v1/scans/{SCAN_A}/findings/{FID}/verify-fix",
        cookies=_auth_cookies(principal),
    )
    assert requested.status_code == 202, requested.text
    assert requested.json()["state"] == "pending"
    assert requested.json()["rescanId"] == str(SCAN_B)

    status = await client.get(
        f"/api/v1/scans/{SCAN_A}/findings/{FID}/verify-fix",
        cookies=_auth_cookies(principal),
    )
    assert status.status_code == 200, status.text
    assert status.json()["state"] == "verified_fixed"


async def test_route_verify_fix_unknown_finding(
    client: AsyncClient, principal, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    async def fake_missing(_self: object, sid: uuid.UUID) -> object:
        raise NotFoundError()

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_missing)
    response = await client.post(
        f"/api/v1/scans/{SCAN_A}/findings/{uuid.uuid4()}/verify-fix",
        cookies=_auth_cookies(principal),
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Migration                                                                   #
# --------------------------------------------------------------------------- #


def test_migration_chain_head_is_0016() -> None:
    from importlib import import_module

    chain = {
        "0014": ("0013", "webhooks"),
        "0015": ("0014", "remediation_verify_link"),
        "0016": ("0015", "remediation_collaboration"),
    }
    for revision, (down, name) in chain.items():
        module = import_module(f"src.infrastructure.database.migrations.versions.{revision}_{name}")
        assert module.revision == revision
        assert module.down_revision == down

    from src.infrastructure.database.models import Base

    assert "verified_in_scan_id" in Base.metadata.tables["finding_remediation"].columns
    for column in ("assignee_user_id", "assigned_at", "assigned_by_user_id", "due_at"):
        assert column in Base.metadata.tables["finding_remediation"].columns
    assert "remediation_comment" in Base.metadata.tables

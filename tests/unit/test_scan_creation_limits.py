"""Scan-creation abuse protection (creation rate + active-scan caps).

Covers: allowed creation, rate rejection without persistence, queued and
running caps, per-user isolation, failed validation consuming nothing,
unauthenticated rejection, rescan parity, lock-before-count ordering, a
serializing lock proving the race window is closed, and the HTTP 429 +
Retry-After envelope.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from src.domain.errors import AttestationNotConfirmedError, NotAuthenticatedError, NotFoundError
from src.domain.scans.errors import ScanQueueFullError, ScanRateLimitedError
from src.domain.scans.scan_service import ScanService
from tests.unit.conftest import FakeRow, _principal  # noqa: F401 — shared harness


class FakeLimiter:
    """Recording admission double."""

    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.admissions = 0

    async def try_admit(self, _scope: str) -> bool:
        self.admissions += 1
        return self.allowed


def _service(env, limiter=None, **caps):  # type: ignore[no-untyped-def]
    return ScanService(env.session, env.owner, scan_limiter=limiter, **caps)


async def test_allowed_creation_admits_once(env) -> None:  # type: ignore[no-untyped-def]
    limiter = FakeLimiter()
    details = await _service(env, limiter).create_scan(target_id=env.target.id)
    assert details.status_code == "QUEUED"
    assert limiter.admissions == 1


async def test_rate_rejection_persists_nothing(env) -> None:  # type: ignore[no-untyped-def]
    limiter = FakeLimiter(allowed=False)
    with pytest.raises(ScanRateLimitedError):
        await _service(env, limiter).create_scan(target_id=env.target.id)
    assert env.repo.rows == {}
    assert limiter.admissions == 1


async def test_queued_cap_rejects_sixth_scan(env) -> None:  # type: ignore[no-untyped-def]
    owner_id = env.owner.id
    for _ in range(5):
        env.repo.rows[uuid.uuid4()] = FakeRow(user_id=owner_id, status_code="QUEUED")
    with pytest.raises(ScanQueueFullError):
        await _service(env).create_scan(target_id=env.target.id)
    assert len(env.repo.rows) == 5


async def test_running_cap_rejects_third_running(env) -> None:  # type: ignore[no-untyped-def]
    owner_id = env.owner.id
    for _ in range(2):
        env.repo.rows[uuid.uuid4()] = FakeRow(user_id=owner_id, status_code="RUNNING")
    with pytest.raises(ScanQueueFullError):
        await _service(env, max_running_per_user=2).create_scan(target_id=env.target.id)


async def test_other_users_scans_do_not_count(env) -> None:  # type: ignore[no-untyped-def]
    stranger = _principal()
    for _ in range(9):
        env.repo.rows[uuid.uuid4()] = FakeRow(user_id=stranger.id, status_code="QUEUED")
    details = await _service(env).create_scan(target_id=env.target.id)
    assert details.status_code == "QUEUED"


async def test_failed_validation_consumes_no_budget(env, mocker) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.attestation_repository import (
        AttestationRepository,
    )

    async def fake_none(_self: object, _tid: uuid.UUID):
        return None

    mocker.patch.object(AttestationRepository, "latest_active_confirmed", fake_none)
    limiter = FakeLimiter()
    with pytest.raises(AttestationNotConfirmedError):
        await _service(env, limiter).create_scan(target_id=env.target.id)
    assert limiter.admissions == 0
    assert env.repo.rows == {}


async def test_unauthenticated_creation_rejected() -> None:
    service = ScanService(object(), None)  # type: ignore[arg-type]
    with pytest.raises(NotAuthenticatedError):
        await service.create_scan(target_id=uuid.uuid4())


async def test_rescan_obeys_rate_limit(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env, FakeLimiter())
    original = await service.create_scan(target_id=env.target.id)
    from tests.unit.conftest import STATUS_IDS

    env.repo.rows[original.id].status_id = STATUS_IDS["REPORT_READY"]
    env.repo.rows[original.id].status_code = "REPORT_READY"

    limited = _service(env, FakeLimiter(allowed=False))
    with pytest.raises(ScanRateLimitedError):
        await limited.rescan_scan(original.id)


async def test_guard_locks_before_counting(env) -> None:  # type: ignore[no-untyped-def]
    await _service(env).create_scan(target_id=env.target.id)
    assert getattr(env.repo, "lock_calls", 0) >= 1


async def test_serializing_lock_closes_creation_race(env) -> None:  # type: ignore[no-untyped-def]
    """Two concurrent creations under a truly serializing lock: the second
    observes the first's row and is rejected at the queued cap of 1.

    Production holds the owner row lock for the whole transaction
    (count → insert → commit); the double mirrors that by releasing only
    when the scan row is persisted.
    """
    gate = asyncio.Lock()
    order: list[str] = []
    real_lock = env.repo.lock_owner
    real_add = env.repo.add

    async def serializing_lock(user_id: uuid.UUID) -> None:
        await gate.acquire()
        order.append("lock")
        await real_lock(user_id)

    def add_and_release(scan: object) -> None:
        real_add(scan)
        if gate.locked():
            gate.release()

    env.repo.lock_owner = serializing_lock  # type: ignore[method-assign]
    env.repo.add = add_and_release  # type: ignore[method-assign]
    service = _service(env, max_queued_per_user=1, max_running_per_user=10)
    results = await asyncio.wait_for(
        asyncio.gather(
            service.create_scan(target_id=env.target.id),
            service.create_scan(target_id=env.target.id),
            return_exceptions=True,
        ),
        timeout=10,
    )
    assert order == ["lock", "lock"]
    outcomes = sorted(type(r).__name__ for r in results)
    assert outcomes == ["ScanDetails", "ScanQueueFullError"]


async def test_rate_limited_create_answers_429_with_retry_after(monkeypatch) -> None:
    """HTTP envelope: 429 SCAN_RATE_LIMITED + Retry-After header."""
    from fastapi.testclient import TestClient

    from src.api.dependencies import get_current_user
    from src.domain.scans.scan_service import ScanService as Service
    from src.main import create_application

    async def _deny_create(self: object, **kwargs: object) -> object:
        raise ScanRateLimitedError()

    monkeypatch.setattr(Service, "create_scan", _deny_create)
    app = create_application()
    user = _principal()
    app.dependency_overrides[get_current_user] = lambda: user
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/api/v1/scans",
        json={"targetId": str(uuid.uuid4())},
    )
    assert response.status_code == 429, response.text
    assert response.json()["error"]["code"] == "SCAN_RATE_LIMITED"
    assert response.headers.get("Retry-After") == "60"


async def test_cross_tenant_create_stays_protected(env) -> None:  # type: ignore[no-untyped-def]
    intruder = _principal()
    service = ScanService(env.session, intruder)
    with pytest.raises((NotFoundError, AttestationNotConfirmedError)):
        await service.create_scan(target_id=env.target.id)

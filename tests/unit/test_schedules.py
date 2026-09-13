"""Scheduled scans: validation, ownership, gated ticks, idempotency.

Schedules automate the existing scan-creation path — they never bypass
it. Tests prove validation, owner scoping, every gate mapping
(attestation/archive/rate/queue/owner), atomic-claim idempotency across
restarts and races, and the HTTP envelope (including enqueue on
creation ticks).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import get_settings
from src.domain.errors import InvalidScheduleError, NotFoundError
from src.domain.schedules.schedule_service import (
    ScheduleService,
    run_due_schedules,
)
from src.domain.users.token_service import create_access_token
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import ScanSchedule, Target, User
from src.infrastructure.database.repositories.user_repository import UserRepository
from src.main import create_application

SETTINGS = get_settings()
NOW = datetime.now(UTC)


def _principal(email: str = "owner@example.com") -> User:
    now = datetime.now(UTC)
    return User(
        id=uuid.uuid4(),
        email=email,
        password_hash="argon2id$fake",
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def _target(owner_id: uuid.UUID, *, archived: bool = False) -> Target:
    now = datetime.now(UTC)
    return Target(
        id=uuid.uuid4(),
        owner_user_id=owner_id,
        hostname="example.com",
        normalized_url="https://example.com/",
        is_archived=archived,
        created_at=now,
    )


def _schedule(owner_id: uuid.UUID, target_id: uuid.UUID, **overrides: object) -> ScanSchedule:
    now = datetime.now(UTC)
    params: dict[str, object] = {
        "id": uuid.uuid4(),
        "owner_user_id": owner_id,
        "target_id": target_id,
        "scan_profile_id": 2,
        "enabled": True,
        "interval_seconds": 3600,
        "next_run_at": now - timedelta(seconds=10),
        "last_run_at": None,
        "last_status": None,
        "last_detail": None,
        "last_scan_id": None,
        "created_at": now,
        "updated_at": now,
    }
    params.update(overrides)
    row = ScanSchedule()
    for key, value in params.items():
        setattr(row, key, value)
    return row


class FakeSession:
    """In-memory session double: staged rows keyed by schedule id."""

    def __init__(self, schedules: list[ScanSchedule] | None = None) -> None:
        self.schedules: dict[uuid.UUID, ScanSchedule] = {s.id: s for s in (schedules or [])}
        self.added: list[object] = []
        self.commits = 0
        self.deleted: list[object] = []

    def add(self, row: object) -> None:
        self.added.append(row)
        if isinstance(row, ScanSchedule):
            self.schedules[row.id] = row

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def delete(self, row: object) -> None:
        self.deleted.append(row)
        if isinstance(row, ScanSchedule):
            self.schedules.pop(row.id, None)


@pytest.fixture
def env(mocker):  # type: ignore[no-untyped-def]
    """Owner + target + doubles for every seam the schedule path touches."""
    owner = _principal()
    target = _target(owner.id)
    session = FakeSession()
    audits: list[dict] = []

    from src.domain.audit.audit_service import AuditService
    from src.domain.scans.scan_service import ScanService
    from src.domain.targets.target_service import TargetService
    from src.infrastructure.database.repositories import scan_repository
    from src.infrastructure.database.repositories.schedule_repository import (
        ScheduleRepository,
    )

    async def fake_get_target(_self: object, target_id: uuid.UUID) -> object:
        if target_id == target.id:
            return SimpleNamespace(id=target.id, is_archived=target.is_archived)
        from src.domain.errors import NotFoundError as _NotFound

        raise _NotFound()

    async def fake_create_scan(_self: object, **kwargs: object) -> object:
        return SimpleNamespace(id=uuid.uuid4(), target_id=kwargs.get("target_id"))

    async def fake_profile_id(_s: object, code: str) -> int:
        profiles = {"quick-check": 1, "standard": 2, "full-assessment": 3}
        if code not in profiles:
            raise LookupError(code)
        return profiles[code]

    async def fake_profile_code(_s: object, profile_id: int) -> str:
        try:
            return {1: "quick-check", 2: "standard", 3: "full-assessment"}[profile_id]
        except KeyError as exc:
            raise LookupError(f"scan_profile id {profile_id} not seeded") from exc

    async def fake_get_by_id(_self: object, user_id: uuid.UUID) -> object | None:
        return owner if user_id == owner.id else None

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(kwargs)

    async def fake_get_for_owner(_self: object, sid: uuid.UUID, oid: uuid.UUID):
        row = session.schedules.get(sid)
        return row if row is not None and row.owner_user_id == oid else None

    async def fake_list_for_owner(_self: object, oid: uuid.UUID):
        return sorted(
            (r for r in session.schedules.values() if r.owner_user_id == oid),
            key=lambda r: r.created_at,
        )

    async def fake_due(_self: object, now: datetime, **kwargs: object):
        return sorted(
            (r for r in session.schedules.values() if r.enabled and r.next_run_at <= now),
            key=lambda r: r.next_run_at,
        )

    async def fake_claim(
        _self: object, sid: uuid.UUID, *, now: datetime, interval_seconds: int
    ) -> bool:
        row = session.schedules.get(sid)
        if row is None or not row.enabled or row.next_run_at > now:
            return False
        row.next_run_at = now + timedelta(seconds=interval_seconds)
        row.last_run_at = now
        return True

    mocker.patch.object(TargetService, "get_target", fake_get_target)
    mocker.patch.object(ScanService, "create_scan", fake_create_scan)
    mocker.patch.object(scan_repository, "_profile_id", fake_profile_id)
    mocker.patch.object(scan_repository, "_profile_code", fake_profile_code)
    mocker.patch.object(UserRepository, "get_by_id", fake_get_by_id)
    mocker.patch.object(AuditService, "record", fake_record)
    mocker.patch.object(ScheduleRepository, "get_for_owner", fake_get_for_owner)
    mocker.patch.object(ScheduleRepository, "list_for_owner", fake_list_for_owner)
    mocker.patch.object(ScheduleRepository, "due_schedules", fake_due)
    mocker.patch.object(ScheduleRepository, "claim_due_schedule", fake_claim)

    import types

    return types.SimpleNamespace(owner=owner, target=target, session=session, audits=audits)


def _service(env) -> ScheduleService:  # type: ignore[no-untyped-def]
    return ScheduleService(env.session, env.owner)


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #


async def test_create_schedule_persists_with_next_run(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    before = datetime.now(UTC)
    details = await service.create_schedule(
        target_id=env.target.id, scan_profile_code="standard", interval_seconds=3600
    )
    assert details.owner_user_id == env.owner.id
    assert details.target_id == env.target.id
    assert details.scan_profile_code == "standard"
    assert details.enabled is True
    assert details.next_run_at.tzinfo is not None
    assert details.next_run_at >= before + timedelta(seconds=3590)
    assert any(a["action_code"] == "SCHEDULE_CREATED" for a in env.audits)


@pytest.mark.parametrize("bad", [59, 0, -5, True, "3600", 99999999, None])
async def test_create_rejects_bad_intervals(env, bad) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    with pytest.raises(InvalidScheduleError):
        await service.create_schedule(target_id=env.target.id, interval_seconds=bad)
    assert not env.session.schedules


async def test_create_rejects_unknown_profile(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    with pytest.raises(InvalidScheduleError):
        await service.create_schedule(target_id=env.target.id, scan_profile_code="nope")


async def test_create_on_foreign_target_is_not_found(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    with pytest.raises(NotFoundError):
        await service.create_schedule(target_id=uuid.uuid4())


# --------------------------------------------------------------------------- #
# Ownership                                                                   #
# --------------------------------------------------------------------------- #


async def test_cross_owner_schedule_is_not_found(env, mocker) -> None:  # type: ignore[no-untyped-def]
    from src.domain.users.user_service import UserAccount

    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id)
    outsider = UserAccount(id=uuid.uuid4(), email="x@y.zz", created_at=NOW)
    foreign = ScheduleService(env.session, outsider)
    with pytest.raises(NotFoundError):
        await foreign.get_schedule(details.id)
    with pytest.raises(NotFoundError):
        await foreign.delete_schedule(details.id)
    assert len(await service.list_schedules()) == 1
    assert await foreign.list_schedules() == []


async def test_delete_removes_and_audits(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id)
    await service.delete_schedule(details.id)
    with pytest.raises(NotFoundError):
        await service.get_schedule(details.id)
    assert any(a["action_code"] == "SCHEDULE_DELETED" for a in env.audits)


async def test_enable_disable(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id)
    disabled = await service.update_schedule(details.id, enabled=False)
    assert disabled.enabled is False
    assert any(a["action_code"] == "SCHEDULE_UPDATED" for a in env.audits)
    outcome = await service.trigger_schedule(details.id)
    assert outcome.status == "skipped_disabled"


async def test_update_interval_and_profile(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id)
    updated = await service.update_schedule(
        details.id, interval_seconds=7200, scan_profile_code="quick-check"
    )
    assert updated.interval_seconds == 7200
    assert updated.scan_profile_code == "quick-check"
    with pytest.raises(InvalidScheduleError):
        await service.update_schedule(details.id, interval_seconds=5)


# --------------------------------------------------------------------------- #
# Gated ticks                                                                 #
# --------------------------------------------------------------------------- #


async def test_successful_tick_creates_scan(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert len(outcomes) == 1
    assert outcomes[0].status == "scan_created"
    assert outcomes[0].scan_id is not None
    refreshed = await service.get_schedule(details.id)
    assert refreshed.last_status == "scan_created"
    assert refreshed.last_scan_id == outcomes[0].scan_id
    assert refreshed.next_run_at > datetime.now(UTC)


async def test_expired_attestation_blocks_without_scan(env, mocker) -> None:  # type: ignore[no-untyped-def]
    from src.domain.errors import AttestationNotConfirmedError
    from src.domain.scans.scan_service import ScanService

    async def fake_denied(_self: object, **kwargs: object) -> object:
        raise AttestationNotConfirmedError()

    mocker.patch.object(ScanService, "create_scan", fake_denied)
    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["blocked_no_attestation"]
    assert all(o.scan_id is None for o in outcomes)


async def test_archived_target_skipped(env) -> None:  # type: ignore[no-untyped-def]
    env.target.is_archived = True
    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["skipped_target_archived"]


@pytest.mark.parametrize("error", ["rate", "queue"])
async def test_rate_and_queue_limits_skip_tick(env, mocker, error: str) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.errors import ScanQueueFullError, ScanRateLimitedError
    from src.domain.scans.scan_service import ScanService

    exc = ScanRateLimitedError() if error == "rate" else ScanQueueFullError()

    async def fake_limited(_self: object, **kwargs: object) -> object:
        raise exc

    mocker.patch.object(ScanService, "create_scan", fake_limited)
    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["skipped_rate_limited"]


async def test_failed_tick_does_not_abort_siblings(env, mocker) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    await service.create_schedule(target_id=env.target.id, interval_seconds=7200)

    calls = {"n": 0}

    async def fake_flaky(_self: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("worker exploded")
        return SimpleNamespace(id=uuid.uuid4(), target_id=kwargs.get("target_id"))

    mocker.patch.object(ScanService, "create_scan", fake_flaky)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=3))
    assert sorted(o.status for o in outcomes) == ["failed", "scan_created"]


async def test_missing_owner_skipped(env, mocker) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.user_repository import UserRepository

    async def fake_gone(_self: object, user_id: uuid.UUID) -> None:
        return None

    mocker.patch.object(UserRepository, "get_by_id", fake_gone)
    env.session.schedules.clear()
    seed = _schedule(env.owner.id, env.target.id)
    env.session.schedules[seed.id] = seed
    outcomes = await run_due_schedules(env.session, datetime.now(UTC))
    assert [o.status for o in outcomes] == ["skipped_owner_inactive"]


# --------------------------------------------------------------------------- #
# Idempotency                                                                 #
# --------------------------------------------------------------------------- #


async def test_duplicate_execution_impossible(env) -> None:  # type: ignore[no-untyped-def]
    """A lost claim race produces no outcome row for the loser."""
    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    now = datetime.now(UTC) + timedelta(hours=2)
    first = await service.run_due_schedules(now)
    assert [o.status for o in first] == ["scan_created"]
    # Second tick immediately after: next_run advanced, nothing due.
    assert await service.run_due_schedules(now) == []


async def test_restart_after_commit_does_not_rerun(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    now = datetime.now(UTC) + timedelta(hours=2)
    await service.run_due_schedules(now)
    await env.session.commit()
    # A restarted worker re-evaluates due state: the won tick is in the
    # future, so the restart creates nothing.
    assert await service.run_due_schedules(now) == []


async def test_stale_next_run_advances_from_now(env) -> None:  # type: ignore[no-untyped-def]
    """Downtime never triggers catch-up storms: next runs from now."""
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    before = datetime.now(UTC)
    await service.run_due_schedules(before + timedelta(days=10))
    refreshed = await service.get_schedule(details.id)
    drift = refreshed.next_run_at - (before + timedelta(days=10, seconds=3600))
    assert abs(drift) <= timedelta(seconds=120)


async def test_trigger_runs_now_and_reschedules(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id)
    outcome = await service.trigger_schedule(details.id)
    assert outcome.status == "scan_created"
    assert outcome.scan_id is not None
    refreshed = await service.get_schedule(details.id)
    assert refreshed.next_run_at > datetime.now(UTC)
    assert refreshed.last_scan_id == outcome.scan_id


async def test_trigger_unknown_is_not_found(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    with pytest.raises(NotFoundError):
        await service.trigger_schedule(uuid.uuid4())


async def test_timezone_aware_timestamps(env) -> None:  # type: ignore[no-untyped-def]
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id)
    assert details.next_run_at.tzinfo is not None
    assert details.created_at.tzinfo is not None


# --------------------------------------------------------------------------- #
# HTTP envelope                                                               #
# --------------------------------------------------------------------------- #


@pytest.fixture
async def client(env, mocker):  # type: ignore[no-untyped-def]
    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield env.session

    application.dependency_overrides[get_db_session] = _overridden_session

    principal = env.owner

    async def fake_get_by_user_id(_self: object, user_id: uuid.UUID):  # type: ignore[no-untyped-def]
        return principal if user_id == principal.id else None

    from src.infrastructure.database.repositories.user_repository import UserRepository

    mocker.patch.object(UserRepository, "get_by_id", fake_get_by_user_id)
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


async def test_route_crud_roundtrip(client: AsyncClient, env, mocker) -> None:  # type: ignore[no-untyped-def]
    created = await client.post(
        "/api/v1/schedules",
        json={
            "targetId": str(env.target.id),
            "scanProfile": "standard",
            "intervalSeconds": 3600,
        },
        cookies=_auth_cookies(env.owner),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["targetId"] == str(env.target.id)
    assert body["intervalSeconds"] == 3600
    assert body["enabled"] is True
    schedule_id = body["id"]

    listed = await client.get("/api/v1/schedules", cookies=_auth_cookies(env.owner))
    assert [s["id"] for s in listed.json()] == [schedule_id]

    patched = await client.patch(
        f"/api/v1/schedules/{schedule_id}",
        json={"enabled": False},
        cookies=_auth_cookies(env.owner),
    )
    assert patched.json()["enabled"] is False

    triggered = await client.post(
        f"/api/v1/schedules/{schedule_id}/trigger", cookies=_auth_cookies(env.owner)
    )
    assert triggered.json()["status"] == "skipped_disabled"

    deleted = await client.delete(
        f"/api/v1/schedules/{schedule_id}", cookies=_auth_cookies(env.owner)
    )
    assert deleted.status_code == 204
    gone = await client.get(f"/api/v1/schedules/{schedule_id}", cookies=_auth_cookies(env.owner))
    assert gone.status_code == 404


async def test_route_invalid_and_foreign(client: AsyncClient, env) -> None:  # type: ignore[no-untyped-def]
    bad = await client.post(
        "/api/v1/schedules",
        json={"targetId": str(env.target.id), "intervalSeconds": 5},
        cookies=_auth_cookies(env.owner),
    )
    assert bad.status_code == 400

    foreign = await client.get(
        f"/api/v1/schedules/{uuid.uuid4()}", cookies=_auth_cookies(env.owner)
    )
    assert foreign.status_code == 404


async def test_route_trigger_enqueues_scan(client: AsyncClient, env, mocker) -> None:  # type: ignore[no-untyped-def]
    import src.workers.scan_tasks as scan_tasks

    enqueued: list[uuid.UUID] = []
    mocker.patch.object(
        scan_tasks, "enqueue_scan", lambda scan_id: enqueued.append(scan_id) or "task-1"
    )
    created = await client.post(
        "/api/v1/schedules",
        json={"targetId": str(env.target.id), "intervalSeconds": 3600},
        cookies=_auth_cookies(env.owner),
    )
    schedule_id = created.json()["id"]
    # Re-enable not needed: fresh schedules start enabled.
    triggered = await client.post(
        f"/api/v1/schedules/{schedule_id}/trigger", cookies=_auth_cookies(env.owner)
    )
    assert triggered.status_code == 200, triggered.text
    assert triggered.json()["status"] == "scan_created"
    assert len(enqueued) == 1


# --------------------------------------------------------------------------- #
# Migration chain                                                             #
# --------------------------------------------------------------------------- #


def test_migration_chain_head_is_0015() -> None:
    from importlib import import_module

    chain = {"0013": "0012", "0014": "0013", "0015": "0014"}
    for revision, down in chain.items():
        module = import_module(
            f"src.infrastructure.database.migrations.versions.{revision}_"
            + {
                "0013": "scan_schedules",
                "0014": "webhooks",
                "0015": "remediation_verify_link",
            }[revision]
        )
        assert module.revision == revision
        assert module.down_revision == down

    from src.infrastructure.database.models import Base

    assert "scan_schedule" in Base.metadata.tables


# --------------------------------------------------------------------------- #
# M6 hardening: invalid/disabled/missing targets, single-path proof,          #
# per-tick audit, claim races, atomic claim+record, gate interaction,         #
# worker-boundary enqueue, and Beat wiring                                    #
# --------------------------------------------------------------------------- #


async def test_disabled_schedule_skipped_via_due_run(env) -> None:  # type: ignore[no-untyped-def]
    """Disabled schedules never execute, including via the worker due path."""
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    await service.update_schedule(details.id, enabled=False)
    before = len([a for a in env.audits if a["action_code"] == "SCHEDULE_RUN"])
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert outcomes == []
    assert len([a for a in env.audits if a["action_code"] == "SCHEDULE_RUN"]) == before
    refreshed = await service.get_schedule(details.id)
    assert refreshed.last_status is None
    assert refreshed.last_scan_id is None


async def test_missing_target_skipped_without_scan(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """A deleted schedule target ticks to skipped_target_unavailable.

    Ownership is enforced at execution time through the same visibility
    gate as interactive scans: a missing/foreign/archived-away target
    creates nothing.
    """
    from src.domain.scans.scan_service import ScanService

    created_scans: list[object] = []

    async def fake_create_scan(_self: object, **kwargs: object) -> object:
        created_scans.append(kwargs)
        return SimpleNamespace(id=uuid.uuid4(), target_id=kwargs.get("target_id"))

    mocker.patch.object(ScanService, "create_scan", fake_create_scan)
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    # Target disappears after the schedule was created (deleted by owner).
    env.session.schedules[details.id].target_id = uuid.uuid4()
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["skipped_target_unavailable"]
    assert created_scans == []
    assert all(o.scan_id is None for o in outcomes)
    refreshed = await service.get_schedule(details.id)
    assert refreshed.last_status == "skipped_target_unavailable"


async def test_invalid_profile_fails_honestly_without_scan(env) -> None:  # type: ignore[no-untyped-def]
    """A schedule whose profile seed vanished records failed, never a scan."""
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    env.session.schedules[details.id].scan_profile_id = 999999
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["failed"]
    assert all(o.scan_id is None for o in outcomes)
    # The schedule row itself is unreadable through the normal detail path
    # while its profile seed is missing (same LookupError as any scan with
    # an unseeded profile); assert on the stored tick state directly.
    row = env.session.schedules[details.id]
    assert row.last_status == "failed"
    assert row.last_scan_id is None


async def test_tick_goes_through_scan_service_create_scan(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """The scheduler has no alternate execution path: ticks call create_scan."""
    from src.domain.scans.scan_service import ScanService

    calls: list[dict] = []

    async def fake_create_scan(_self: object, **kwargs: object) -> object:
        calls.append(dict(kwargs))
        return SimpleNamespace(id=uuid.uuid4(), target_id=kwargs.get("target_id"))

    mocker.patch.object(ScanService, "create_scan", fake_create_scan)
    service = _service(env)
    await service.create_schedule(
        target_id=env.target.id, scan_profile_code="standard", interval_seconds=3600
    )
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["scan_created"]
    assert len(calls) == 1
    assert calls[0]["target_id"] == env.target.id
    assert calls[0]["scan_profile_code"] == "standard"


async def test_every_tick_emits_schedule_run_audit(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """Every claimed tick is auditable: one SCHEDULE_RUN per outcome.

    Success, gate-blocked, and failed ticks all append the run event with
    the owner id (fail-closed audit visibility), the outcome status, and
    the created scan id when there is one.
    """
    from src.domain.scans.scan_service import ScanService

    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    await service.create_schedule(target_id=env.target.id, interval_seconds=7200)

    calls = {"n": 0}

    async def fake_flaky(_self: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("worker exploded")
        return SimpleNamespace(id=uuid.uuid4(), target_id=kwargs.get("target_id"))

    mocker.patch.object(ScanService, "create_scan", fake_flaky)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=3))
    assert sorted(o.status for o in outcomes) == ["failed", "scan_created"]

    runs = [a for a in env.audits if a["action_code"] == "SCHEDULE_RUN"]
    assert len(runs) == 2
    by_status = {str(a["metadata_json"]["status"]): a for a in runs}
    assert set(by_status) == {"failed", "scan_created"}
    for audit in runs:
        assert audit["metadata_json"]["ownerUserId"] == str(env.owner.id)
        assert audit["actor_user_id"] == env.owner.id
    assert by_status["scan_created"]["metadata_json"]["scanId"] is not None
    assert by_status["failed"]["metadata_json"]["scanId"] is None


async def test_blocked_tick_is_audited_with_no_scan(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """Expired or revoked attestations block the tick, audit it, create nothing."""
    from src.domain.errors import AttestationNotConfirmedError
    from src.domain.scans.scan_service import ScanService

    async def fake_denied(_self: object, **kwargs: object) -> object:
        raise AttestationNotConfirmedError()

    mocker.patch.object(ScanService, "create_scan", fake_denied)
    service = _service(env)
    await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["blocked_no_attestation"]
    runs = [a for a in env.audits if a["action_code"] == "SCHEDULE_RUN"]
    assert len(runs) == 1
    assert runs[0]["metadata_json"]["status"] == "blocked_no_attestation"
    assert runs[0]["metadata_json"]["scanId"] is None


async def test_claim_race_loser_produces_no_outcome(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """A worker that loses the atomic claim creates no scan and no outcome."""
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.schedule_repository import (
        ScheduleRepository,
    )

    created: list[object] = []

    async def fake_create_scan(_self: object, **kwargs: object) -> object:
        created.append(kwargs)
        return SimpleNamespace(id=uuid.uuid4(), target_id=kwargs.get("target_id"))

    async def fake_lost_claim(_self: object, sid: uuid.UUID, **kwargs: object) -> bool:
        return False

    mocker.patch.object(ScanService, "create_scan", fake_create_scan)
    mocker.patch.object(ScheduleRepository, "claim_due_schedule", fake_lost_claim)
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    # Force the schedule due without going through the real claim path.
    env.session.schedules[details.id].next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    assert await service.run_due_schedules(datetime.now(UTC)) == []
    assert created == []
    refreshed = await service.get_schedule(details.id)
    assert refreshed.last_status is None
    assert not [a for a in env.audits if a["action_code"] == "SCHEDULE_RUN"]


async def test_claim_and_record_commit_atomically(env) -> None:  # type: ignore[no-untyped-def]
    """Claim, outcome stamp, and audit row land in one caller-committed unit.

    The service never commits: a crash before the caller's commit rolls
    back claim + stamp + audit together (idempotent retry re-runs the
    tick), while a crash after commit never re-runs it.
    """
    service = _service(env)
    details = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    commits_before = env.session.commits
    outcomes = await service.run_due_schedules(datetime.now(UTC) + timedelta(hours=2))
    assert [o.status for o in outcomes] == ["scan_created"]
    assert env.session.commits == commits_before  # caller (worker/route) owns commit
    refreshed = await service.get_schedule(details.id)
    assert refreshed.last_status == "scan_created"
    assert refreshed.next_run_at > datetime.now(UTC)
    runs = [a for a in env.audits if a["action_code"] == "SCHEDULE_RUN"]
    assert len(runs) == 1
    assert runs[0]["metadata_json"]["scanId"] == str(outcomes[0].scan_id)


async def test_scheduled_creation_ignores_gate_but_dispatch_does_not(env) -> None:  # type: ignore[no-untyped-def]
    """The scanner execution gate applies at dispatch, never at creation.

    Scheduled ticks create QUEUED scans exactly like interactive creation;
    ``enqueue_scan`` is the single gate both paths share (proven by the
    worker-tier gate tests): with the gate off it dispatches nothing.
    """
    from src.config.settings import get_settings
    from src.workers.scan_tasks import enqueue_scan

    settings = get_settings()
    original = settings.scanner_execution_enabled
    object.__setattr__(settings, "scanner_execution_enabled", False)
    try:
        service = _service(env)
        details = await service.create_schedule(target_id=env.target.id)
        outcome = await service.trigger_schedule(details.id)
        assert outcome.status == "scan_created"
        assert outcome.scan_id is not None
        assert enqueue_scan(outcome.scan_id) == ""
    finally:
        object.__setattr__(settings, "scanner_execution_enabled", original)


async def test_due_tick_worker_enqueues_only_created_scans(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """Worker boundary: only scan_created ticks dispatch; skips never do."""
    import src.infrastructure.database.connection as connection
    import src.workers.schedule_tasks as schedule_tasks

    sent: list[uuid.UUID] = []
    mocker.patch.object(
        schedule_tasks, "enqueue_scan", lambda scan_id: sent.append(scan_id) or "task-1"
    )

    class _Context:
        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return env.session

        async def __aexit__(self, *args: object) -> bool:
            return False

    class _Maker:
        def __call__(self) -> _Context:
            return _Context()

    mocker.patch.object(connection, "get_async_sessionmaker", lambda: _Maker())

    service = _service(env)
    good = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    blocked = await service.create_schedule(target_id=env.target.id, interval_seconds=3600)
    await service.update_schedule(blocked.id, enabled=False)
    for row in env.session.schedules.values():
        row.next_run_at = datetime.now(UTC) - timedelta(seconds=1)

    serializable = await schedule_tasks._run_due_tick()
    assert [row["status"] for row in serializable] == ["scan_created"]
    assert [row["schedule_id"] for row in serializable] == [str(good.id)]
    assert len(sent) == 1


def test_beat_schedule_claims_due_ticks_every_minute() -> None:
    """Beat wiring: the stock beat schedule ticks due schedules each minute."""
    from src.workers.celery_app import celery_app

    beat = dict(celery_app.conf.beat_schedule or {})
    assert "run-due-schedules-every-minute" in beat
    entry = beat["run-due-schedules-every-minute"]
    assert entry["task"] == "src.workers.schedule_tasks.run_due_schedules_task"
    routes = dict(celery_app.conf.task_routes or {})
    assert routes["src.workers.schedule_tasks.run_due_schedules_task"]["queue"] == "scan"

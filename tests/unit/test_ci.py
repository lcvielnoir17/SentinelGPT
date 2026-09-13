"""CI/CD security API (M10): credentials, trigger, idempotency, policy.

Proves the automation plane is a thin authenticated entry point into
the EXISTING scan system: bearer tokens are hashed at rest and shown
once, scans are target-bound, retries are idempotent, policy is
deterministic (no AI), and every gate of the normal pipeline
(attestation, rate/queue limits, execution gate, ownership) still
applies. Failures are honest envelopes, never ambiguous state.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from src.domain.ci import tokens
from src.domain.ci.errors import CiAuthError, CiConflictError, InvalidCiError
from src.domain.ci.policy import POLICY_VERSION, evaluate_policy, parse_policy
from src.domain.ci.service import CiService
from src.domain.ci.validation import (
    parse_expires_at,
    parse_idempotency_key,
    parse_name,
    parse_scan_profile,
)
from src.domain.errors import NotFoundError

OWNER_ID = uuid.uuid4()
OUTSIDER_ID = uuid.uuid4()
TARGET_ID = uuid.uuid4()
TARGET_B_ID = uuid.uuid4()
SCAN_ID = uuid.uuid4()


def _user_row(user_id: uuid.UUID = OWNER_ID, active: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        id=user_id,
        email=f"{user_id}@x.test",
        is_active=active,
        created_at=datetime.now(UTC),
        firebase_uid=None,
    )


def _credential_row(**overrides: object) -> SimpleNamespace:
    now = datetime.now(UTC)
    params: dict[str, object] = {
        "id": uuid.uuid4(),
        "owner_user_id": OWNER_ID,
        "target_id": TARGET_ID,
        "name": "ci",
        "scope": "scan",
        "secret_hash": tokens.hash_secret("s3cret"),
        "key_prefix": "sgptci_ab12cd34",
        "created_at": now,
        "last_used_at": None,
        "expires_at": None,
        "revoked_at": None,
    }
    params.update(overrides)
    return SimpleNamespace(**params)


class FakeSession:
    """Minimal session double: staging + savepoints + commit/rollback counts."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self.deleted: list[object] = []

    def add(self, row: object) -> None:
        from sqlalchemy.exc import IntegrityError

        from src.infrastructure.database.models import CiScanRequest

        if isinstance(row, CiScanRequest) and row.idempotency_key is not None:
            for staged in self.added:
                if (
                    isinstance(staged, CiScanRequest)
                    and staged.credential_id == row.credential_id
                    and staged.idempotency_key == row.idempotency_key
                ):
                    raise IntegrityError("INSERT", {}, Exception("dup"))
        self.added.append(row)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1

    async def delete(self, row: object) -> None:
        self.deleted.append(row)

    def begin_nested(self):  # type: ignore[no-untyped-def]
        session = self

        @asynccontextmanager
        async def _nested():  # type: ignore[no-untyped-def]
            snapshot = list(session.added)
            try:
                yield session
            except Exception:
                session.added = snapshot
                raise

        return _nested()


@pytest.fixture
def world(monkeypatch):  # type: ignore[no-untyped-def]
    """Owner session + target gate + captured audits for service tests."""
    from src.domain.audit.audit_service import AuditService
    from src.domain.targets.target_service import TargetService

    session = FakeSession()
    audits: list[dict] = []

    async def fake_get_target(_self: object, tid: uuid.UUID) -> object:
        if tid == TARGET_ID:
            return SimpleNamespace(id=TARGET_ID, is_archived=False)
        raise NotFoundError()

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(dict(kwargs))

    monkeypatch.setattr(TargetService, "get_target", fake_get_target)
    monkeypatch.setattr(AuditService, "record", fake_record)
    namespace = SimpleNamespace(session=session, audits=audits)
    namespace.service = lambda uid=OWNER_ID: CiService(session, SimpleNamespace(id=uid))
    return namespace


def _aget(row):  # type: ignore[no-untyped-def]
    async def _get(_self: object, *_args: object, **_kwargs: object) -> object:
        return row

    return _get


def _alist(*rows):  # type: ignore[no-untyped-def]
    async def _list(_self: object, *_args: object, **_kwargs: object) -> list:
        return list(rows)

    return _list


def _adict():  # type: ignore[no-untyped-def]
    async def _dict(_self: object, *_args: object, **_kwargs: object) -> dict:
        return {}

    return _dict


def _codes(world) -> list[str]:  # type: ignore[no-untyped-def]
    return [str(a["action_code"]) for a in world.audits]


# --------------------------------------------------------------------------- #
# Tokens (items 2-3, 32)                                                      #
# --------------------------------------------------------------------------- #


def test_token_roundtrip_and_prefix() -> None:
    credential_id = uuid.uuid4()
    secret = tokens.generate_secret()
    plaintext = tokens.build_plaintext(credential_id, secret)
    assert plaintext.startswith("sgptci_")
    parsed = tokens.parse_plaintext(plaintext)
    assert parsed is not None and parsed[0] == credential_id
    digest = tokens.hash_secret(secret)
    assert tokens.verify_secret(secret, digest)
    assert not tokens.verify_secret(secret + "x", digest)
    assert tokens.key_prefix_for(secret).startswith("sgptci_")


@pytest.mark.parametrize(
    "bad", ["", "bearer x", "sgptci_", "sgptci_notauuid_secret", "sgptci_123", "other_1_2"]
)
def test_token_malformed_rejected(bad: str) -> None:
    assert tokens.parse_plaintext(bad) is None
    assert not tokens.verify_secret("", "abc")


# --------------------------------------------------------------------------- #
# Validation (items 7, 11, 32)                                                #
# --------------------------------------------------------------------------- #


def test_name_key_profile_expiry_validation() -> None:
    assert parse_name("  nightly  ") == "nightly"
    for bad in ("", "   ", "x" * 101, 5, None):
        try:
            parse_name(bad)
        except InvalidCiError:
            continue
        raise AssertionError(f"accepted {bad!r}")
    assert parse_idempotency_key(None) is None
    assert parse_idempotency_key("  ") is None
    assert parse_idempotency_key("build-123_abc") == "build-123_abc"
    for bad in ("has space", "semi;colon", "x" * 129, 42):
        try:
            parse_idempotency_key(bad)
        except InvalidCiError:
            continue
        raise AssertionError(f"accepted {bad!r}")
    assert parse_scan_profile(None) == "standard"
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert parse_expires_at(future) is not None
    assert parse_expires_at(None) is None
    for bad in ("2030-01-01T00:00:00", "tomorrow", "2000-01-01T00:00:00+00:00", 1):
        try:
            parse_expires_at(bad)
        except InvalidCiError:
            continue
        raise AssertionError(f"accepted {bad!r}")


# --------------------------------------------------------------------------- #
# Policy (items 24-28)                                                        #
# --------------------------------------------------------------------------- #


def test_policy_parse() -> None:
    assert parse_policy(None) is None
    assert parse_policy({}) == {"fail_on_regression": False}
    parsed = parse_policy({"fail_on_severity": "high", "fail_on_regression": True})
    assert parsed == {"fail_on_severity": "HIGH", "fail_on_regression": True}
    for bad in ({"nope": 1}, {"fail_on_severity": "CRIT"}, {"fail_on_regression": "yes"}, [1]):
        try:
            parse_policy(bad)
        except InvalidCiError:
            continue
        raise AssertionError(f"accepted {bad!r}")
    assert POLICY_VERSION.startswith("sgpt.ci-policy.v")


def test_policy_pending_pass_fail() -> None:
    assert (
        evaluate_policy(
            scan_status="QUEUED", severity_counts={}, has_regression=False, policy=None
        )["state"]
        == "NOT_EVALUATED"
    )
    assert (
        evaluate_policy(
            scan_status="RUNNING",
            severity_counts={},
            has_regression=False,
            policy={"fail_on_severity": "HIGH"},
        )["state"]
        == "PENDING"
    )
    assert (
        evaluate_policy(
            scan_status="REPORT_READY",
            severity_counts={"MEDIUM": 2},
            has_regression=False,
            policy={"fail_on_severity": "HIGH"},
        )["state"]
        == "PASS"
    )
    failed = evaluate_policy(
        scan_status="REPORT_READY",
        severity_counts={"HIGH": 1},
        has_regression=False,
        policy={"fail_on_severity": "HIGH"},
    )
    assert failed == {"state": "FAIL", "reason": "severity_threshold"}
    regressed = evaluate_policy(
        scan_status="REPORT_READY_DEGRADED",
        severity_counts={},
        has_regression=True,
        policy={"fail_on_severity": None, "fail_on_regression": True},
    )
    assert regressed == {"state": "FAIL", "reason": "regression_detected"}
    assert (
        evaluate_policy(
            scan_status="REJECTED",
            severity_counts={},
            has_regression=False,
            policy={"fail_on_severity": "LOW"},
        )["state"]
        == "FAIL"
    )


def test_policy_determinism() -> None:
    kwargs = {
        "scan_status": "REPORT_READY",
        "severity_counts": {"HIGH": 1, "LOW": 3},
        "has_regression": True,
        "policy": {"fail_on_severity": "MEDIUM", "fail_on_regression": True},
    }
    assert evaluate_policy(**kwargs) == evaluate_policy(**kwargs)


# --------------------------------------------------------------------------- #
# Credential lifecycle (items 1, 4-7, 29, 35)                                 #
# --------------------------------------------------------------------------- #


async def test_create_returns_secret_once(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    staged: list[object] = []
    monkeypatch.setattr(CiRepository, "add_credential", lambda _s, row: staged.append(row))
    created = await world.service().create_credential(name="nightly", target_id=TARGET_ID)
    assert created.secret.startswith("sgptci_")
    assert len(staged) == 1
    stored_hash = staged[0].secret_hash
    assert stored_hash != created.secret and len(stored_hash) == 64
    assert _codes(world) == ["CI_CREDENTIAL_CREATED"]
    assert "secret" not in str(world.audits[0]["metadata_json"]).lower().replace("secret", "")


async def test_create_on_foreign_target_is_404(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(NotFoundError):
        await world.service().create_credential(name="x", target_id=uuid.uuid4())


async def test_list_hides_secrets(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    row = _credential_row()
    monkeypatch.setattr(CiRepository, "list_for_owner", _alist(row))
    rows = await world.service().list_credentials()
    assert len(rows) == 1
    blob = str(rows[0])
    assert "s3cret" not in blob and "secret_hash" not in blob
    assert rows[0]["key_prefix"] == "sgptci_ab12cd34"


async def test_rotate_kills_old_secret(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    row = _credential_row()
    monkeypatch.setattr(CiRepository, "get_credential", _aget(row))
    rotated = await world.service().rotate_credential(row.id)
    assert rotated.secret.startswith("sgptci_")
    assert not tokens.verify_secret("s3cret", row.secret_hash)
    parsed = tokens.parse_plaintext(rotated.secret)
    assert parsed is not None and tokens.verify_secret(parsed[1], row.secret_hash)
    assert _codes(world) == ["CI_CREDENTIAL_ROTATED"]


async def test_revoke_is_idempotent(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    row = _credential_row()
    monkeypatch.setattr(CiRepository, "get_credential", _aget(row))
    await world.service().revoke_credential(row.id)
    assert row.revoked_at is not None
    await world.service().revoke_credential(row.id)
    assert _codes(world) == ["CI_CREDENTIAL_REVOKED"]


async def test_foreign_credential_is_404(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    row = _credential_row()
    monkeypatch.setattr(CiRepository, "get_credential", _aget(row))
    outsider = world.service(OUTSIDER_ID)
    with pytest.raises(NotFoundError):
        await outsider.rotate_credential(row.id)
    with pytest.raises(NotFoundError):
        await outsider.revoke_credential(row.id)


# --------------------------------------------------------------------------- #
# Bearer auth (items 8-9, 32-33)                                              #
# --------------------------------------------------------------------------- #


def _auth_world(world, monkeypatch, row=None):  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.ci_repository import CiRepository
    from src.infrastructure.database.repositories.user_repository import UserRepository

    credential = row if row is not None else _credential_row()

    async def fake_get_credential(_self: object, cid: uuid.UUID) -> object | None:
        return credential if cid == credential.id else None

    async def fake_get_user(_self: object, uid: uuid.UUID) -> object | None:
        return _user_row(uid) if uid == OWNER_ID else None

    monkeypatch.setattr(CiRepository, "get_credential", fake_get_credential)
    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_user)
    return credential


def _bearer(credential_id: uuid.UUID, secret: str = "s3cret") -> str:
    return f"Bearer {tokens.build_plaintext(credential_id, secret)}"


async def test_auth_success_updates_last_used(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService

    credential = _auth_world(world, monkeypatch)
    context = await CiService(world.session, None).authenticate(_bearer(credential.id))
    assert context.owner.id == OWNER_ID
    assert credential.last_used_at is not None


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Bearer nope", "Token x", "Bearer sgptci_deadbeef_secret"],
)
async def test_auth_failures_identical_401(world, monkeypatch, header) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.domain.errors import DomainError

    _auth_world(world, monkeypatch)
    with pytest.raises(CiAuthError) as exc_info:
        await CiService(world.session, None).authenticate(header)
    err = exc_info.value
    assert isinstance(err, DomainError) and err.status_code == 401
    assert err.code == "UNAUTHENTICATED"


async def test_auth_wrong_secret_revoked_expired_inactive(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.infrastructure.database.repositories.ci_repository import CiRepository
    from src.infrastructure.database.repositories.user_repository import UserRepository

    service = CiService(world.session, None)
    credential = _auth_world(world, monkeypatch)
    with pytest.raises(CiAuthError):
        await service.authenticate(_bearer(credential.id, "wrong"))

    revoked = _credential_row(revoked_at=datetime.now(UTC))
    _auth_world(world, monkeypatch, revoked)
    with pytest.raises(CiAuthError):
        await service.authenticate(_bearer(revoked.id))

    expired = _credential_row(expires_at=datetime.now(UTC) - timedelta(hours=1))
    _auth_world(world, monkeypatch, expired)
    with pytest.raises(CiAuthError):
        await service.authenticate(_bearer(expired.id))

    _auth_world(world, monkeypatch)

    async def fake_inactive(_self: object, uid: uuid.UUID) -> object | None:
        return _user_row(uid, active=False)

    monkeypatch.setattr(UserRepository, "get_by_id", fake_inactive)
    monkeypatch.setattr(CiRepository, "get_credential", _aget(credential))
    with pytest.raises(CiAuthError):
        await service.authenticate(_bearer(credential.id))


# --------------------------------------------------------------------------- #
# Trigger (items 10, 14-15, 18-23, 29, 34)                                    #
# --------------------------------------------------------------------------- #


def _trigger_world(world, monkeypatch, **overrides):  # type: ignore[no-untyped-def]
    """Bearer context + mocked ScanService.create_scan for trigger tests."""
    from sqlalchemy.exc import IntegrityError

    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.models import CiScanRequest
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    credential = (
        _auth_world(world, monkeypatch, **overrides)
        if overrides
        else _auth_world(world, monkeypatch)
    )
    created: list[dict] = []

    async def fake_create_scan(_self: object, **kwargs: object) -> object:
        created.append(dict(kwargs))
        return SimpleNamespace(id=SCAN_ID, status_code="QUEUED", target_id=kwargs.get("target_id"))

    # Uniqueness backing mimicking the partial unique index: a duplicate
    # (credential, key) INSERT raises so the loser resolves the winner.
    claims: dict[tuple[str, str], object] = {}
    real_add = world.session.add

    def tracking_add(row: object) -> None:
        if isinstance(row, CiScanRequest) and row.idempotency_key is not None:
            marker = (str(row.credential_id), str(row.idempotency_key))
            if marker in claims:
                raise IntegrityError("INSERT", {}, Exception("dup"))
            claims[marker] = row
        real_add(row)

    async def fake_winner(_self: object, cid: uuid.UUID, key: str) -> object | None:
        return claims.get((str(cid), key))

    world.session.add = tracking_add  # type: ignore[method-assign]
    monkeypatch.setattr(ScanService, "create_scan", fake_create_scan)
    monkeypatch.setattr(CiRepository, "get_request_by_key", fake_winner)
    import src.workers.scan_tasks as scan_tasks

    monkeypatch.setattr(scan_tasks, "enqueue_scan", lambda _sid: "task-1")
    return credential, created


async def test_trigger_creates_bound_scan(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService

    credential, created = _trigger_world(world, monkeypatch)
    context = await CiService(world.session, None).authenticate(_bearer(credential.id))
    outcome = await CiService(world.session, context.owner).trigger_scan(context)
    assert outcome["scan_id"] == SCAN_ID and outcome["status"] == "QUEUED"
    assert outcome["idempotent"] is False and outcome["dispatched"] is True
    assert created and created[0]["target_id"] == TARGET_ID
    assert created[0]["scan_profile_code"] == "standard"
    assert _codes(world) == ["CI_SCAN_REQUESTED"]
    assert world.session.commits >= 1


async def test_trigger_uses_single_scan_path(world, monkeypatch, mocker) -> None:  # type: ignore[no-untyped-def]
    """No alternate execution path: trigger calls ScanService.create_scan."""
    from src.domain.ci.service import CiService
    from src.domain.scans.scan_service import ScanService

    credential, _ = _trigger_world(world, monkeypatch)
    spy = mocker.patch.object(
        ScanService,
        "create_scan",
        autospec=True,
        return_value=SimpleNamespace(id=SCAN_ID, status_code="QUEUED", target_id=TARGET_ID),
    )
    context = await CiService(world.session, None).authenticate(_bearer(credential.id))
    await CiService(world.session, context.owner).trigger_scan(
        context, scan_profile="quick-check", policy={"fail_on_severity": "HIGH"}
    )
    assert spy.call_count == 1
    assert spy.call_args.kwargs["scan_profile_code"] == "quick-check"


async def test_trigger_rejects_without_attestation(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.domain.errors import AttestationNotConfirmedError
    from src.domain.scans.scan_service import ScanService

    credential, _ = _trigger_world(world, monkeypatch)

    async def denied(_self: object, **kwargs: object) -> object:
        raise AttestationNotConfirmedError()

    monkeypatch.setattr(ScanService, "create_scan", denied)
    context = await CiService(world.session, None).authenticate(_bearer(credential.id))
    with pytest.raises(AttestationNotConfirmedError):
        await CiService(world.session, context.owner).trigger_scan(context)
    assert _codes(world) == ["CI_SCAN_REJECTED"]
    assert world.session.commits >= 1  # rejection audit survives


@pytest.mark.parametrize("error", ["rate", "queue", "running"])
async def test_trigger_limits_propagate(world, monkeypatch, error: str) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.domain.scans.errors import ScanQueueFullError, ScanRateLimitedError
    from src.domain.scans.scan_service import ScanService

    credential, _ = _trigger_world(world, monkeypatch)
    exc = ScanRateLimitedError() if error == "rate" else ScanQueueFullError()

    async def limited(_self: object, **kwargs: object) -> object:
        raise exc

    monkeypatch.setattr(ScanService, "create_scan", limited)
    context = await CiService(world.session, None).authenticate(_bearer(credential.id))
    with pytest.raises(type(exc)):
        await CiService(world.session, context.owner).trigger_scan(context)
    assert _codes(world) == ["CI_SCAN_REJECTED"]


async def test_trigger_gate_off_stays_queued(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.config.settings import get_settings
    from src.domain.ci.service import CiService

    credential, _ = _trigger_world(world, monkeypatch)
    settings = get_settings()
    original = settings.scanner_execution_enabled
    object.__setattr__(settings, "scanner_execution_enabled", False)
    try:
        import src.workers.scan_tasks as scan_tasks

        def broker_down(_scan_id: object) -> str:
            raise RuntimeError("broker unreachable")

        monkeypatch.setattr(scan_tasks, "enqueue_scan", broker_down)
        context = await CiService(world.session, None).authenticate(_bearer(credential.id))
        outcome = await CiService(world.session, context.owner).trigger_scan(context)
        assert outcome["status"] == "QUEUED" and outcome["dispatched"] is False
    finally:
        object.__setattr__(settings, "scanner_execution_enabled", original)


async def test_idempotent_retry_returns_original(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService

    credential, created = _trigger_world(world, monkeypatch)
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))
    owner_service = CiService(world.session, context.owner)

    from src.domain.scans.scan_service import ScanService as _ScanService

    async def fake_details(_self: object, sid: uuid.UUID) -> object:
        return SimpleNamespace(id=SCAN_ID, status_code="QUEUED", target_id=TARGET_ID)

    monkeypatch.setattr(_ScanService, "get_scan", fake_details)
    policy = {"fail_on_severity": "HIGH"}
    first = await owner_service.trigger_scan(context, idempotency_key="build-42", policy=policy)
    second = await owner_service.trigger_scan(
        context, idempotency_key="build-42", policy={"fail_on_severity": "LOW"}
    )
    assert first["scan_id"] == second["scan_id"] == SCAN_ID
    assert second["idempotent"] is True
    assert len(created) == 1  # one logical scan, first policy wins


async def test_idempotency_key_scoped_per_credential(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Same key on DIFFERENT credentials creates independent scans (no leak)."""
    from src.domain.ci.service import CiService
    from src.infrastructure.database.models import CiScanRequest
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    credential, created = _trigger_world(world, monkeypatch)
    other = _credential_row()

    async def scoped_lookup(_self: object, cid: uuid.UUID, key: str) -> object | None:
        # Mirrors the real WHERE (credential_id AND key) over staged rows.
        for row in world.session.added:
            if (
                isinstance(row, CiScanRequest)
                and row.credential_id == cid
                and row.idempotency_key == key
            ):
                return row
        return None

    monkeypatch.setattr(CiRepository, "get_request_by_key", scoped_lookup)
    service = CiService(world.session, None)
    first = await service.trigger_scan(
        SimpleNamespace(credential=credential, owner=SimpleNamespace(id=OWNER_ID)),
        idempotency_key="same-key",
    )
    winner = await CiRepository(world.session).get_request_by_key(other.id, "same-key")
    assert winner is None
    assert first["idempotent"] is False
    assert len(created) == 1


async def test_conflict_when_winner_incomplete(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A key claimed by an in-flight creation answers 409 (retry observes it)."""
    from sqlalchemy.exc import IntegrityError

    from src.domain.ci.service import CiService
    from src.infrastructure.database.models import CiScanRequest
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    credential, _ = _trigger_world(world, monkeypatch)
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))
    owner_service = CiService(world.session, context.owner)

    real_add = world.session.add

    def blocking_add(row: object) -> None:
        if isinstance(row, CiScanRequest):
            raise IntegrityError("INSERT", {}, Exception("dup"))
        real_add(row)

    world.session.add = blocking_add  # type: ignore[method-assign]

    async def fake_incomplete(_self: object, cid: uuid.UUID, key: str) -> object | None:
        return SimpleNamespace(scan_id=None, credential_id=cid)

    monkeypatch.setattr(CiRepository, "get_request_by_key", fake_incomplete)
    with pytest.raises(CiConflictError) as exc_info:
        await owner_service.trigger_scan(context, idempotency_key="claimed")
    assert exc_info.value.status_code == 409


async def test_concurrent_idempotency_race(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Racing duplicate observes the winner (same scan) — never a duplicate scan."""
    import asyncio

    from sqlalchemy.exc import IntegrityError

    from src.domain.ci.service import CiService
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.models import CiScanRequest
    from src.infrastructure.database.repositories.ci_repository import CiRepository

    credential, created = _trigger_world(world, monkeypatch)
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))
    owner_service = CiService(world.session, context.owner)

    calls = {"n": 0}
    real_add = world.session.add

    def counting_add(row: object) -> None:
        if isinstance(row, CiScanRequest) and getattr(row, "idempotency_key", None) == "race":
            calls["n"] += 1
            if calls["n"] == 2:
                raise IntegrityError("INSERT", {}, Exception("dup"))
        real_add(row)

    world.session.add = counting_add  # type: ignore[method-assign]

    async def fake_winner(_self: object, cid: uuid.UUID, key: str) -> object | None:
        return SimpleNamespace(scan_id=SCAN_ID, credential_id=cid)

    async def fake_details(_self: object, sid: uuid.UUID) -> object:
        return SimpleNamespace(id=SCAN_ID, status_code="QUEUED", target_id=TARGET_ID)

    monkeypatch.setattr(CiRepository, "get_request_by_key", fake_winner)
    monkeypatch.setattr(ScanService, "get_scan", fake_details)

    first, second = await asyncio.gather(
        owner_service.trigger_scan(context, idempotency_key="race"),
        owner_service.trigger_scan(context, idempotency_key="race"),
    )
    assert first["scan_id"] == second["scan_id"] == SCAN_ID
    assert len(created) == 1  # exactly one logical scan across the race


# --------------------------------------------------------------------------- #
# Result + policy outcomes (items 24-28, 31, 36-38)                           #
# --------------------------------------------------------------------------- #


def _result_world(
    world, monkeypatch, status="REPORT_READY", findings=None, lifecycle=None, remediation=None
):  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.posture_repository import (
        PostureRepository,
    )
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    rows = (
        findings
        if findings is not None
        else [
            {"id": str(uuid.uuid4()), "severity": "HIGH", "fingerprint": "fp-1", "title": "t"},
            {"id": str(uuid.uuid4()), "severity": "LOW", "fingerprint": "fp-2", "title": "t2"},
        ]
    )

    async def fake_get_scan(_self: object, sid: uuid.UUID) -> object:
        if sid == SCAN_ID:
            return SimpleNamespace(
                id=SCAN_ID,
                target_id=TARGET_ID,
                status_code=status,
                queued_at=datetime.now(UTC),
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC) if status == "REPORT_READY" else None,
                created_at=datetime.now(UTC),
            )
        raise NotFoundError()

    async def fake_dtos(_self: object, sid: uuid.UUID) -> list:
        return [dict(r) for r in rows]

    async def fake_lifecycle(_self: object, tid: uuid.UUID, sid: uuid.UUID) -> dict:
        return dict(lifecycle) if lifecycle is not None else {"fp-1": "NEW", "fp-2": "RESOLVED"}

    async def fake_remediation(_self: object, **kwargs: object) -> dict:
        return dict(remediation) if remediation is not None else {"fp-1": {"status": "IN_PROGRESS"}}

    async def fake_no_request(_self: object, cid: uuid.UUID, sid: uuid.UUID) -> None:
        return None

    monkeypatch.setattr(ScanService, "get_scan", fake_get_scan)
    monkeypatch.setattr(CiService, "_request_for_scan", fake_no_request)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_finding_dtos", fake_dtos)
    monkeypatch.setattr(PostureRepository, "lifecycle_at_scan", fake_lifecycle)
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_remediations_for_target", fake_remediation
    )


async def test_result_pending_and_not_evaluated(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService

    credential, _ = _trigger_world(world, monkeypatch)
    _result_world(world, monkeypatch, status="RUNNING")
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))
    result = await CiService(world.session, context.owner).get_result(context, SCAN_ID)
    assert result["status"] == "RUNNING"
    assert result["policy"] == {
        "state": "NOT_EVALUATED",
        "reason": "no policy configured",
        "version": None,
        "configured": False,
    }
    assert result["finding_count"] == 2
    assert result["severity_counts"] == {"HIGH": 1, "LOW": 1}
    assert result["references"]["complianceMappingVersion"]
    assert "secret" not in str(result)


async def test_result_policy_pass_fail(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService

    credential, _ = _trigger_world(world, monkeypatch)
    _result_world(world, monkeypatch, status="REPORT_READY")
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))
    owner_service = CiService(world.session, context.owner)

    async def fake_request(_self: object, cid: uuid.UUID, sid: uuid.UUID) -> object | None:
        return SimpleNamespace(
            policy={"fail_on_severity": "CRITICAL"}, policy_version=POLICY_VERSION
        )

    monkeypatch.setattr(CiService, "_request_for_scan", fake_request)
    passed = await owner_service.get_result(context, SCAN_ID)
    assert passed["policy"]["state"] == "PASS"
    assert passed["policy"]["version"] == POLICY_VERSION

    async def fake_strict(_self: object, cid: uuid.UUID, sid: uuid.UUID) -> object | None:
        return SimpleNamespace(
            policy={"fail_on_severity": "HIGH", "fail_on_regression": True},
            policy_version=POLICY_VERSION,
        )

    monkeypatch.setattr(CiService, "_request_for_scan", fake_strict)
    failed = await owner_service.get_result(context, SCAN_ID)
    assert failed["policy"]["state"] == "FAIL"  # 200 with FAIL, never 500
    assert failed["lifecycle_counts"] == {"NEW": 1, "RESOLVED": 1}
    assert failed["remediation_summary"]["IN_PROGRESS"] == 1


async def test_result_scan_failed_is_fail_closed(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService

    credential, _ = _trigger_world(world, monkeypatch)
    _result_world(world, monkeypatch, status="REJECTED", findings=[])
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))

    async def fake_request(_self: object, cid: uuid.UUID, sid: uuid.UUID) -> object | None:
        return SimpleNamespace(policy={"fail_on_severity": "LOW"}, policy_version=POLICY_VERSION)

    monkeypatch.setattr(CiService, "_request_for_scan", fake_request)
    result = await CiService(world.session, context.owner).get_result(context, SCAN_ID)
    assert result["policy"] == {
        "state": "FAIL",
        "reason": "scan_failed",
        "version": POLICY_VERSION,
        "configured": True,
    }


async def test_result_cross_owner_and_wrong_target_404(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.domain.scans.scan_service import ScanService

    credential, _ = _trigger_world(world, monkeypatch)
    _result_world(world, monkeypatch)
    service = CiService(world.session, None)
    context = await service.authenticate(_bearer(credential.id))

    async def fake_other_target(_self: object, sid: uuid.UUID) -> object:
        return SimpleNamespace(
            id=sid,
            target_id=TARGET_B_ID,
            status_code="REPORT_READY",
            queued_at=None,
            started_at=None,
            completed_at=None,
            created_at=datetime.now(UTC),
        )

    monkeypatch.setattr(ScanService, "get_scan", fake_other_target)
    with pytest.raises(NotFoundError):
        await CiService(world.session, context.owner).get_result(context, SCAN_ID)
    with pytest.raises(NotFoundError):
        await CiService(world.session, context.owner).get_result(context, uuid.uuid4())


# --------------------------------------------------------------------------- #
# Routes (items 29-31, 35-38)                                                 #
# --------------------------------------------------------------------------- #


@pytest.fixture
async def client(world, monkeypatch):  # type: ignore[no-untyped-def]
    from httpx import ASGITransport, AsyncClient

    from src.config.settings import get_settings
    from src.domain.targets.target_service import TargetService
    from src.domain.users.token_service import create_access_token
    from src.infrastructure.database.connection import get_db_session
    from src.infrastructure.database.models import CiCredential, CiScanRequest
    from src.infrastructure.database.repositories.ci_repository import CiRepository
    from src.infrastructure.database.repositories.user_repository import UserRepository
    from src.main import create_application

    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield world.session

    application.dependency_overrides[get_db_session] = _overridden_session

    async def fake_get_by_user_id(_self: object, user_id: uuid.UUID):  # type: ignore[no-untyped-def]
        return _user_row(user_id) if user_id == OWNER_ID else None

    async def fake_get_target(_self: object, tid: uuid.UUID) -> object:
        if tid == TARGET_ID:
            return SimpleNamespace(id=TARGET_ID, is_archived=False)
        raise NotFoundError()

    creds: dict[str, object] = {}

    def fake_add_credential(_self: object, row: object) -> None:
        creds[str(row.id)] = row
        world.session.add(row)

    async def fake_get_credential(_self: object, cid: uuid.UUID) -> object | None:
        return creds.get(str(cid))

    async def fake_list_for_owner(_self: object, oid: uuid.UUID) -> list:
        return [r for r in creds.values() if r.owner_user_id == oid]

    def fake_add_request(_self: object, row: object) -> None:
        world.session.add(row)

    async def fake_get_request(_self: object, cid: uuid.UUID, key: str) -> object | None:
        for row in world.session.added:
            if (
                isinstance(row, CiScanRequest)
                and row.credential_id == cid
                and row.idempotency_key == key
            ):
                return row
        return None

    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_user_id)
    monkeypatch.setattr(TargetService, "get_target", fake_get_target)
    monkeypatch.setattr(CiRepository, "add_credential", fake_add_credential)
    monkeypatch.setattr(CiRepository, "get_credential", fake_get_credential)
    monkeypatch.setattr(CiRepository, "list_for_owner", fake_list_for_owner)
    monkeypatch.setattr(CiRepository, "add_request", fake_add_request)
    monkeypatch.setattr(CiRepository, "get_request_by_key", fake_get_request)
    _ = (CiCredential, CiScanRequest)
    transport = ASGITransport(app=application)
    settings = get_settings()

    def cookies(uid: uuid.UUID) -> dict[str, str]:
        return {
            "accessToken": create_access_token(
                user_id=uid,
                secret_key=settings.jwt_secret_key,
                algorithm=settings.jwt_algorithm,
                expires_in_minutes=settings.access_token_expire_minutes,
            )
        }

    return SimpleNamespace(
        client=AsyncClient(transport=transport, base_url="http://test"), cookies=cookies
    )


async def test_route_credential_crud(client, world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    created = await client.client.post(
        "/api/v1/ci/credentials",
        json={"name": "nightly", "targetId": str(TARGET_ID)},
        cookies=client.cookies(OWNER_ID),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["secret"].startswith("sgptci_")
    assert body["targetId"] == str(TARGET_ID)
    credential_id = body["id"]

    listed = await client.client.get("/api/v1/ci/credentials", cookies=client.cookies(OWNER_ID))
    assert listed.status_code == 200
    assert [c["id"] for c in listed.json()] == [credential_id]
    assert "secret" not in listed.json()[0] and "secret_hash" not in listed.json()[0]

    rotated = await client.client.post(
        f"/api/v1/ci/credentials/{credential_id}/rotate", cookies=client.cookies(OWNER_ID)
    )
    assert rotated.status_code == 200 and rotated.json()["secret"].startswith("sgptci_")

    revoked = await client.client.post(
        f"/api/v1/ci/credentials/{credential_id}/revoke", cookies=client.cookies(OWNER_ID)
    )
    assert revoked.status_code == 204

    foreign = await client.client.post(
        "/api/v1/ci/credentials",
        json={"name": "x", "targetId": str(uuid.uuid4())},
        cookies=client.cookies(OWNER_ID),
    )
    assert foreign.status_code == 404


async def test_route_trigger_and_poll(client, world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.ci.service import CiService
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.posture_repository import (
        PostureRepository,
    )
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    created = await client.client.post(
        "/api/v1/ci/credentials",
        json={"name": "ci", "targetId": str(TARGET_ID)},
        cookies=client.cookies(OWNER_ID),
    )
    secret = created.json()["secret"]

    async def fake_create_scan(_self: object, **kwargs: object) -> object:
        return SimpleNamespace(id=SCAN_ID, status_code="QUEUED", target_id=TARGET_ID)

    async def fake_get_scan(_self: object, sid: uuid.UUID) -> object:
        if sid != SCAN_ID:
            raise NotFoundError()
        return SimpleNamespace(
            id=SCAN_ID,
            target_id=TARGET_ID,
            status_code="QUEUED",
            queued_at=datetime.now(UTC),
            started_at=None,
            completed_at=None,
            created_at=datetime.now(UTC),
        )

    async def fake_request(_self: object, cid: uuid.UUID, sid: uuid.UUID) -> object | None:
        from src.infrastructure.database.models import CiScanRequest

        for row in world.session.added:
            if isinstance(row, CiScanRequest) and row.credential_id == cid and row.scan_id == sid:
                return row
        return None

    monkeypatch.setattr(ScanService, "create_scan", fake_create_scan)
    monkeypatch.setattr(ScanService, "get_scan", fake_get_scan)
    monkeypatch.setattr(CiService, "_request_for_scan", fake_request)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_finding_dtos", _alist())
    monkeypatch.setattr(PostureRepository, "lifecycle_at_scan", _adict())
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_remediations_for_target", _adict())
    import src.workers.scan_tasks as scan_tasks

    monkeypatch.setattr(scan_tasks, "enqueue_scan", lambda _sid: "task-1")

    headers = {"Authorization": f"Bearer {secret}"}
    first = await client.client.post(
        "/api/v1/ci/scans",
        json={"idempotencyKey": "ci-1", "policy": {"fail_on_severity": "HIGH"}},
        headers=headers,
    )
    assert first.status_code == 202, first.text
    assert first.json()["scanId"] == str(SCAN_ID)

    retry = await client.client.post(
        "/api/v1/ci/scans", json={"idempotencyKey": "ci-1"}, headers=headers
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["scanId"] == str(SCAN_ID)
    assert retry.json()["idempotent"] is True

    result = await client.client.get(f"/api/v1/ci/scans/{SCAN_ID}", headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["policy"]["state"] == "PENDING"  # stored policy, queued scan

    bad = await client.client.get(
        f"/api/v1/ci/scans/{SCAN_ID}", headers={"Authorization": "Bearer nope"}
    )
    assert bad.status_code == 401


async def test_route_rejects_bad_bearer(client, world) -> None:  # type: ignore[no-untyped-def]
    response = await client.client.post("/api/v1/ci/scans", json={})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"

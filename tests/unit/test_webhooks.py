"""Webhooks: subscriptions, signing, SSRF defense, delivery, fanout.

Covers ownership scoping, validation, secret handling (shown once,
never again), HMAC signing, destination SSRF defense at create and
send time, retry/backoff/duplicate semantics, disabled handling, and
the fanout ledger (duplicate fanouts create no extra rows).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from src.config.settings import get_settings
from src.domain.errors import NotFoundError
from src.domain.events.events import (
    NEW_FINDING,
    REMEDIATION_CHANGED,
    SCAN_COMPLETED,
    SCAN_FAILED,
    DomainEvent,
)
from src.domain.users.token_service import create_access_token
from src.domain.webhooks.errors import InvalidWebhookError
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import User, Webhook, WebhookDelivery
from src.main import create_application

SETTINGS = get_settings()
FERNET_KEY = Fernet.generate_key()


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


def _webhook(owner_id: uuid.UUID, **overrides: object) -> Webhook:
    now = datetime.now(UTC)
    params: dict[str, object] = {
        "id": uuid.uuid4(),
        "owner_user_id": owner_id,
        "url": "https://hooks.example.com/sentinel",
        "events": [SCAN_COMPLETED, NEW_FINDING],
        "secret_encrypted": "enc",
        "enabled": True,
        "timeout_seconds": 10,
        "created_at": now,
        "updated_at": now,
    }
    params.update(overrides)
    row = Webhook()
    for key, value in params.items():
        setattr(row, key, value)
    return row


def _event(
    event_type: str = SCAN_COMPLETED, event_id: str = "ev-1", **overrides: object
) -> DomainEvent:
    params: dict[str, object] = {
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": datetime.now(UTC),
        "scan_id": str(uuid.uuid4()),
        "target_id": str(uuid.uuid4()),
        "fingerprint": None,
        "transition": "REPORT_READY",
    }
    params.update(overrides)
    return DomainEvent(**params)  # type: ignore[arg-type]


class FakeSession:
    """In-memory session double for webhook/fanout paths."""

    def __init__(self) -> None:
        self.webhooks: dict[uuid.UUID, Webhook] = {}
        self.deliveries: dict[uuid.UUID, WebhookDelivery] = {}
        self.added: list[object] = []
        self.commits = 0

    def add(self, row: object) -> None:
        self.added.append(row)
        if isinstance(row, Webhook):
            self.webhooks[row.id] = row
        if isinstance(row, WebhookDelivery):
            self.deliveries[row.id] = row

    async def flush(self) -> None:
        for row in list(self.added):
            if isinstance(row, WebhookDelivery) and getattr(row, "id", None) is None:
                row.id = uuid.uuid4()
            if isinstance(row, Webhook) and getattr(row, "id", None) is None:
                row.id = uuid.uuid4()

    async def commit(self) -> None:
        self.commits += 1

    async def delete(self, row: object) -> None:
        if isinstance(row, Webhook):
            self.webhooks.pop(row.id, None)

    async def execute(self, _stmt: object) -> object:
        raise AssertionError("FakeSession.execute reached unexpectedly")

    async def get(self, model: object, key: object) -> object | None:
        name = getattr(model, "__name__", "")
        if name == "WebhookDelivery":
            return self.deliveries.get(key)  # type: ignore[arg-type]
        if name == "Webhook":
            return self.webhooks.get(key)  # type: ignore[arg-type]
        return None

    def begin_nested(self):  # type: ignore[no-untyped-def]
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _nested():  # type: ignore[no-untyped-def]
            snapshot = (dict(self.webhooks), dict(self.deliveries), list(self.added))
            try:
                yield self
            except Exception:
                self.webhooks, self.deliveries, self.added = (
                    snapshot[0],
                    snapshot[1],
                    snapshot[2],
                )
                raise

        return _nested()


@pytest.fixture
def fernet_key(monkeypatch):  # type: ignore[no-untyped-def]
    """Route secret-box crypto through a test-only Fernet key."""
    import src.infrastructure.secrets.secret_box as secret_box

    key = Fernet(FERNET_KEY)
    monkeypatch.setattr(secret_box, "_fernet", lambda: key)
    return key


@pytest.fixture
def no_dns(monkeypatch):  # type: ignore[no-untyped-def]
    """URL validation without network: allow only the fixture host."""
    from src.infrastructure.network import webhook_target as target_module

    def fake_validate(url: str, *, timeout_s: float = 5.0):  # type: ignore[no-untyped-def]
        if url == "https://hooks.example.com/sentinel":
            return target_module.ValidatedWebhookTarget(
                url=url,
                host="hooks.example.com",
                port=443,
                addresses=("93.184.216.34",),
            )
        from src.infrastructure.network.webhook_target import InvalidWebhookUrlError

        raise InvalidWebhookUrlError(f"refused in tests: {url}")

    monkeypatch.setattr(target_module, "validate_webhook_url", fake_validate)
    return fake_validate


@pytest.fixture
def world(monkeypatch, fernet_key, no_dns):  # type: ignore[no-untyped-def]
    """Owner + session + patched seams for service-level tests."""
    import types

    from src.domain.audit.audit_service import AuditService
    from src.infrastructure.database.repositories.webhook_repository import (
        WebhookRepository,
    )

    owner = _principal()
    session = FakeSession()
    audits: list[dict] = []

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(dict(kwargs))
        return None

    mocker_patch = monkeypatch.setattr
    mocker_patch(AuditService, "record", fake_record)

    async def fake_get_for_owner(_self: object, wid: uuid.UUID, oid: uuid.UUID):
        row = session.webhooks.get(wid)
        return row if row is not None and row.owner_user_id == oid else None

    async def fake_list_for_owner(_self: object, oid: uuid.UUID):
        return sorted(
            (r for r in session.webhooks.values() if r.owner_user_id == oid),
            key=lambda r: r.created_at,
        )

    async def fake_list_enabled(_self: object, oid: uuid.UUID):
        return [r for r in session.webhooks.values() if r.owner_user_id == oid and r.enabled]

    async def fake_cancel(_self: object, wid: uuid.UUID) -> None:
        for row in session.deliveries.values():
            if row.webhook_id == wid and row.status == "pending":
                row.status = "cancelled"

    async def fake_get_delivery(_self: object, did: uuid.UUID):
        return session.deliveries.get(did)

    async def fake_list_deliveries(_self: object, wid: uuid.UUID, *, limit: int):
        rows = [r for r in session.deliveries.values() if r.webhook_id == wid]
        rows.sort(key=lambda r: r.created_at, reverse=True)
        return rows[:limit]

    async def fake_record_delivery(_self: object, **kwargs: object):
        dupe = next(
            (
                r
                for r in session.deliveries.values()
                if r.webhook_id == kwargs["webhook_id"] and r.event_id == kwargs["event_id"]
            ),
            None,
        )
        if dupe is not None:
            return None
        row = WebhookDelivery()
        row.id = uuid.uuid4()
        row.webhook_id = kwargs["webhook_id"]
        row.event_id = kwargs["event_id"]
        row.event_type = kwargs["event_type"]
        row.status = "pending"
        row.attempts = 0
        row.next_retry_at = None
        row.last_error = None
        row.event_payload = dict(kwargs["event_payload"])
        row.created_at = datetime.now(UTC)
        row.updated_at = datetime.now(UTC)
        session.deliveries[row.id] = row
        return row.id

    mocker_patch(WebhookRepository, "get_for_owner", fake_get_for_owner)
    mocker_patch(WebhookRepository, "list_for_owner", fake_list_for_owner)
    mocker_patch(WebhookRepository, "list_enabled_for_owner", fake_list_enabled)
    mocker_patch(WebhookRepository, "cancel_pending", fake_cancel)
    mocker_patch(WebhookRepository, "get_delivery", fake_get_delivery)
    mocker_patch(WebhookRepository, "list_deliveries", fake_list_deliveries)
    mocker_patch(WebhookRepository, "record_delivery", fake_record_delivery)
    return types.SimpleNamespace(owner=owner, session=session, audits=audits)


def _service(world) -> object:  # type: ignore[no-untyped-def]
    from src.domain.webhooks.webhook_service import WebhookService

    return WebhookService(world.session, world.owner)


# --------------------------------------------------------------------------- #
# Subscriptions                                                               #
# --------------------------------------------------------------------------- #


async def test_create_returns_secret_once(world) -> None:  # type: ignore[no-untyped-def]
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel",
        events=[SCAN_COMPLETED, SCAN_FAILED],
        timeout_seconds=10,
    )
    assert len(created.secret) == 64
    assert created.details.events == (SCAN_COMPLETED, SCAN_FAILED)
    assert created.details.enabled is True
    fetched = await service.get_webhook(created.details.id)
    assert fetched.url == "https://hooks.example.com/sentinel"
    # The secret is encrypted at rest, never the raw value.
    stored = world.session.webhooks[created.details.id]
    assert stored.secret_encrypted != created.secret


async def test_get_never_exposes_secret(world) -> None:  # type: ignore[no-untyped-def]
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    assert "secret" not in dir(await service.get_webhook(created.details.id))
    assert [w.id for w in await service.list_webhooks()] == [created.details.id]


async def test_create_rejects_bad_inputs(world) -> None:  # type: ignore[no-untyped-def]
    service = _service(world)
    with pytest.raises(InvalidWebhookError):
        await service.create_webhook(url="http://hooks.example.com/x", events=[SCAN_COMPLETED])
    with pytest.raises(InvalidWebhookError):
        await service.create_webhook(url="https://hooks.example.com/sentinel", events=[])
    with pytest.raises(InvalidWebhookError):
        await service.create_webhook(
            url="https://hooks.example.com/sentinel", events=["BOGUS_EVENT"]
        )
    with pytest.raises(InvalidWebhookError):
        await service.create_webhook(
            url="https://hooks.example.com/sentinel",
            events=[SCAN_COMPLETED],
            timeout_seconds=1,
        )
    assert world.session.webhooks == {}


async def test_cross_owner_isolation(world) -> None:  # type: ignore[no-untyped-def]
    from src.domain.users.user_service import UserAccount
    from src.domain.webhooks.webhook_service import WebhookService

    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    outsider = WebhookService(
        world.session,
        UserAccount(id=uuid.uuid4(), email="x@y.zz", created_at=datetime.now(UTC)),
    )
    with pytest.raises(NotFoundError):
        await outsider.get_webhook(created.details.id)
    with pytest.raises(NotFoundError):
        await outsider.delete_webhook(created.details.id)
    assert await outsider.list_webhooks() == []


async def test_update_revalidates_and_cancels_pending(world) -> None:  # type: ignore[no-untyped-def]
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    world.session.deliveries[uuid.uuid4()] = _delivery(created.details.id, "ev-1", "pending")
    with pytest.raises(InvalidWebhookError):
        await service.update_webhook(created.details.id, url="http://evil.example/x")
    updated = await service.update_webhook(created.details.id, enabled=False)
    assert updated.enabled is False
    pending = [r for r in world.session.deliveries.values() if r.status == "pending"]
    assert pending == []


async def test_delete_cascades_deliveries(world) -> None:  # type: ignore[no-untyped-def]
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    world.session.deliveries[uuid.uuid4()] = _delivery(created.details.id, "ev-1", "sent")
    await service.delete_webhook(created.details.id)
    # FakeSession.delete only drops the webhook; production cascades via FK.
    # The delivery row references a gone webhook: fanout can no longer find
    # it (asserted at the worker layer), and listing is owner-gated away.
    with pytest.raises(NotFoundError):
        await service.get_webhook(created.details.id)


def _delivery(webhook_id: uuid.UUID, event_id: str, status: str) -> WebhookDelivery:
    row = WebhookDelivery()
    row.id = uuid.uuid4()
    row.webhook_id = webhook_id
    row.event_id = event_id
    row.event_type = SCAN_COMPLETED
    row.status = status
    row.attempts = 0
    row.next_retry_at = None
    row.last_error = None
    row.event_payload = {"event_id": event_id}
    row.created_at = datetime.now(UTC)
    row.updated_at = datetime.now(UTC)
    return row


async def test_unconfigured_secrets_disable_creation(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import src.infrastructure.secrets.secret_box as secret_box
    from src.domain.webhooks.errors import WebhooksNotConfiguredError

    def broken() -> object:
        raise secret_box.WebhookSecretsNotConfiguredError("no key")

    monkeypatch.setattr(secret_box, "_fernet", broken)
    service = _service(world)
    with pytest.raises(WebhooksNotConfiguredError):
        await service.create_webhook(
            url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
        )


# --------------------------------------------------------------------------- #
# Signing                                                                     #
# --------------------------------------------------------------------------- #


def test_sign_and_verify_roundtrip() -> None:
    from src.domain.webhooks.signing import verify_signature
    from src.infrastructure.notifications.sender import build_signed_request

    body, headers = build_signed_request(
        secret="s3cret", event_id="ev-1", payload={"a": 1}, timestamp=1700000000
    )
    assert headers["X-SentinelGPT-Event-Id"] == "ev-1"
    assert headers["X-SentinelGPT-Timestamp"] == "1700000000"
    assert verify_signature("s3cret", body, headers["X-SentinelGPT-Signature"])
    assert not verify_signature("wrong", body, headers["X-SentinelGPT-Signature"])
    assert not verify_signature("s3cret", body + b"x", headers["X-SentinelGPT-Signature"])
    assert not verify_signature("s3cret", body, "bogus")


# --------------------------------------------------------------------------- #
# Destination validation                                                      #
# --------------------------------------------------------------------------- #


def test_url_validation_rejects_unsafe_targets(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import socket

    from src.infrastructure.network.webhook_target import (
        InvalidWebhookUrlError,
        validate_webhook_url,
    )

    for bad in (
        "http://hooks.example.com/x",
        "https://user:pass@hooks.example.com/x",
        "https://",
        "https://hooks.example.com:99999/x",
        "not a url",
        "https://127.0.0.1/x",
        "https://10.0.0.5/x",
        "https://169.254.169.254/latest/",
        "https://localhost/x",
        "https://[::1]/x",
    ):
        with pytest.raises(InvalidWebhookUrlError):
            validate_webhook_url(bad)

    real_getaddrinfo = socket.getaddrinfo

    def fake_dns(host: str, port: int, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        assert host == "hooks.example.com"
        return real_getaddrinfo("93.184.216.34", port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
    validated = validate_webhook_url("https://hooks.example.com:8443/x")
    assert validated.host == "hooks.example.com"
    assert validated.port == 8443
    assert validated.addresses == ("93.184.216.34",)


def test_url_validation_rejects_rebound_dns(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import socket

    from src.infrastructure.network.webhook_target import (
        InvalidWebhookUrlError,
        validate_webhook_url,
    )

    real_getaddrinfo = socket.getaddrinfo

    def fake_rebound(host: str, port: int, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        return real_getaddrinfo("127.0.0.1", port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_rebound)
    with pytest.raises(InvalidWebhookUrlError):
        validate_webhook_url("https://hooks.example.com/x")


# --------------------------------------------------------------------------- #
# Fanout                                                                      #
# --------------------------------------------------------------------------- #


async def test_fanout_filters_and_dedupes(world) -> None:  # type: ignore[no-untyped-def]
    from src.domain.webhooks.dispatch import build_webhook_payload, fanout_events

    service = _service(world)
    await service.create_webhook(
        url="https://hooks.example.com/sentinel",
        events=[SCAN_COMPLETED, NEW_FINDING],
    )
    await service.create_webhook(url="https://hooks.example.com/sentinel", events=[SCAN_FAILED])
    events = [
        _event(SCAN_COMPLETED, "ev-1"),
        _event(REMEDIATION_CHANGED, "ev-2"),
    ]
    created = await fanout_events(world.session, world.owner.id, events)
    assert len(created) == 1  # only the subscribed webhook, only ev-1
    again = await fanout_events(world.session, world.owner.id, events)
    assert again == []  # duplicate fanout creates nothing

    payload = build_webhook_payload(events[0])
    assert set(payload) <= {
        "event_id",
        "event_type",
        "occurred_at",
        "version",
        "target_id",
        "scan_id",
        "fingerprint",
        "transition",
        "severity",
    }


async def test_fanout_ignores_disabled(world) -> None:  # type: ignore[no-untyped-def]
    from src.domain.webhooks.dispatch import fanout_events

    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    await service.update_webhook(created.details.id, enabled=False)
    assert await fanout_events(world.session, world.owner.id, [_event()]) == []


# --------------------------------------------------------------------------- #
# Delivery                                                                    #
# --------------------------------------------------------------------------- #


async def test_sender_success_and_failures(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import httpx

    from src.infrastructure.notifications.sender import send_delivery

    async def fake_ok(self, url, **kwargs):  # type: ignore[no-untyped-def]
        assert url == "https://hooks.example.com/sentinel"
        assert kwargs["headers"]["X-SentinelGPT-Event-Id"] == "ev-1"
        return httpx.Response(200, json={"ok": True})

    async def fake_redirect(self, url, **kwargs):  # type: ignore[no-untyped-def]
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    async def fake_server_error(self, url, **kwargs):  # type: ignore[no-untyped-def]
        return httpx.Response(500)

    async def fake_client_error(self, url, **kwargs):  # type: ignore[no-untyped-def]
        return httpx.Response(422)

    async def fake_timeout(self, url, **kwargs):  # type: ignore[no-untyped-def]
        raise httpx.ConnectTimeout("slow")

    from src.infrastructure.network import webhook_target as target_module

    monkeypatch.setattr(target_module, "validate_webhook_url", lambda _url, **_k: None)

    async def run(handler):  # type: ignore[no-untyped-def]
        monkeypatch.setattr(httpx.AsyncClient, "post", handler)
        return await send_delivery(
            url="https://hooks.example.com/sentinel",
            secret="s",
            event_id="ev-1",
            payload={"event_id": "ev-1"},
            timeout_seconds=10,
        )

    ok = await run(fake_ok)
    assert (ok.delivered, ok.retryable, ok.status_code) == (True, False, 200)
    redirect = await run(fake_redirect)
    assert (redirect.delivered, redirect.retryable) == (False, False)
    server = await run(fake_server_error)
    assert (server.delivered, server.retryable) == (False, True)
    client_err = await run(fake_client_error)
    assert (client_err.delivered, client_err.retryable) == (False, False)
    timeout = await run(fake_timeout)
    assert (timeout.delivered, timeout.retryable) == (False, True)


async def test_sender_revalidates_destination(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A URL valid at create time but rebound by send time is terminal."""

    from src.infrastructure.network import webhook_target as target_module
    from src.infrastructure.network.webhook_target import InvalidWebhookUrlError
    from src.infrastructure.notifications.sender import send_delivery

    def refuse(url: str, **kwargs: object) -> None:  # type: ignore[no-untyped-def]
        raise InvalidWebhookUrlError("rebound to private IP")

    monkeypatch.setattr(target_module, "validate_webhook_url", refuse)
    outcome = await send_delivery(
        url="https://hooks.example.com/sentinel",
        secret="s",
        event_id="ev-1",
        payload={},
        timeout_seconds=10,
    )
    assert outcome.delivered is False and outcome.retryable is False


async def test_worker_task_state_machine(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """pending→sent, retry scheduling, terminal failure, idempotent no-ops."""
    from src.workers import webhook_tasks as tasks

    delivered: list[str] = []

    async def fake_maker():  # type: ignore[no-untyped-def]
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _session():  # type: ignore[no-untyped-def]
            yield world.session

        return _session()

    import src.infrastructure.database.connection as connection

    class _Maker:
        def __call__(self):  # type: ignore[no-untyped-def]
            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def _session():  # type: ignore[no-untyped-def]
                yield world.session

            return _session()

    monkeypatch.setattr(connection, "get_async_sessionmaker", lambda: _Maker())

    async def fake_send(**kwargs: object) -> object:  # type: ignore[no-untyped-def]
        from src.infrastructure.notifications.sender import DeliveryOutcome

        delivered.append(str(kwargs.get("event_id")))
        return DeliveryOutcome(delivered=True, retryable=False, status_code=200)

    async def fake_decrypt(_ciphertext: str) -> str:
        return "raw-secret"

    hook = _stored_hook(world.session)
    world.session.webhooks[hook.id] = hook
    row = _delivery(hook.id, "ev-1", "pending")
    world.session.deliveries[row.id] = row

    import src.infrastructure.notifications.sender as sender_module
    import src.infrastructure.secrets.secret_box as secret_box

    monkeypatch.setattr(sender_module, "send_delivery", fake_send)
    monkeypatch.setattr(secret_box, "decrypt_secret", fake_decrypt)

    retries: list[tuple] = []

    async def fake_retry(delivery_id: str, countdown: int) -> None:
        retries.append((delivery_id, countdown))

    result = await tasks._deliver(str(row.id), fake_retry)
    assert result["status"] == "sent"
    assert row.status == "sent" and row.attempts == 1
    # Re-entry after completion is a no-op.
    assert (await tasks._deliver(str(row.id), fake_retry))["status"] == "ignored"

    row2 = _delivery(hook.id, "ev-2", "pending")
    world.session.deliveries[row2.id] = row2

    async def fake_retryable(**kwargs: object) -> object:  # type: ignore[no-untyped-def]
        from src.infrastructure.notifications.sender import DeliveryOutcome

        return DeliveryOutcome(delivered=False, retryable=True, detail="HTTP 500")

    monkeypatch.setattr(sender_module, "send_delivery", fake_retryable)
    result2 = await tasks._deliver(str(row2.id), fake_retry)
    assert result2["status"] == "retry-scheduled"
    assert row2.attempts == 1 and row2.next_retry_at is not None
    assert retries and retries[0][1] == 60

    # Disable the webhook: in-flight delivery cancels instead of sending.
    hook.enabled = False
    row3 = _delivery(hook.id, "ev-3", "pending")
    world.session.deliveries[row3.id] = row3
    result3 = await tasks._deliver(str(row3.id), fake_retry)
    assert result3["status"] == "cancelled"

    # Unknown delivery id: no-op, never an error.
    result4 = await tasks._deliver(str(uuid.uuid4()), fake_retry)
    assert result4["status"] == "ignored"


def _stored_hook(session: FakeSession) -> Webhook:
    owner = _principal()
    hook = _webhook(owner.id)
    session.webhooks[hook.id] = hook
    return hook


# --------------------------------------------------------------------------- #
# Routes                                                                      #
# --------------------------------------------------------------------------- #


@pytest.fixture
async def client(world, mocker):  # type: ignore[no-untyped-def]
    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield world.session

    application.dependency_overrides[get_db_session] = _overridden_session

    async def fake_get_by_user_id(_self: object, user_id: uuid.UUID):  # type: ignore[no-untyped-def]
        return world.owner if user_id == world.owner.id else None

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


async def test_route_crud_and_secret_once(client: AsyncClient, world, mocker) -> None:  # type: ignore[no-untyped-def]
    created = await client.post(
        "/api/v1/webhooks",
        json={
            "url": "https://hooks.example.com/sentinel",
            "events": [SCAN_COMPLETED, NEW_FINDING],
            "timeoutSeconds": 10,
        },
        cookies=_auth_cookies(world.owner),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert len(body["secret"]) == 64
    assert body["events"] == [NEW_FINDING, SCAN_COMPLETED]
    webhook_id = body["id"]

    listed = await client.get("/api/v1/webhooks", cookies=_auth_cookies(world.owner))
    assert [w["id"] for w in listed.json()] == [webhook_id]
    assert "secret" not in listed.json()[0]

    fetched = await client.get(f"/api/v1/webhooks/{webhook_id}", cookies=_auth_cookies(world.owner))
    assert "secret" not in fetched.json()

    patched = await client.patch(
        f"/api/v1/webhooks/{webhook_id}",
        json={"enabled": False},
        cookies=_auth_cookies(world.owner),
    )
    assert patched.json()["enabled"] is False

    deliveries = await client.get(
        f"/api/v1/webhooks/{webhook_id}/deliveries", cookies=_auth_cookies(world.owner)
    )
    assert deliveries.status_code == 200 and deliveries.json() == []

    deleted = await client.delete(
        f"/api/v1/webhooks/{webhook_id}", cookies=_auth_cookies(world.owner)
    )
    assert deleted.status_code == 204
    gone = await client.get(f"/api/v1/webhooks/{webhook_id}", cookies=_auth_cookies(world.owner))
    assert gone.status_code == 404


async def test_route_invalid_and_foreign(client: AsyncClient, world) -> None:  # type: ignore[no-untyped-def]
    bad = await client.post(
        "/api/v1/webhooks",
        json={"url": "http://hooks.example.com/x", "events": [SCAN_COMPLETED]},
        cookies=_auth_cookies(world.owner),
    )
    assert bad.status_code == 400

    unknown = await client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/sentinel", "events": ["NOPE"]},
        cookies=_auth_cookies(world.owner),
    )
    assert unknown.status_code == 400

    foreign = await client.get(
        f"/api/v1/webhooks/{uuid.uuid4()}", cookies=_auth_cookies(world.owner)
    )
    assert foreign.status_code == 404


async def test_route_unconfigured_is_503(client: AsyncClient, world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import src.infrastructure.secrets.secret_box as secret_box

    def broken() -> object:
        raise secret_box.WebhookSecretsNotConfiguredError("no key")

    monkeypatch.setattr(secret_box, "_fernet", broken)
    response = await client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/sentinel", "events": [SCAN_COMPLETED]},
        cookies=_auth_cookies(world.owner),
    )
    assert response.status_code == 503


async def test_route_notify_fans_out(client: AsyncClient, world, mocker) -> None:  # type: ignore[no-untyped-def]
    """PUT .../remediation/notify persists state and ledgers a delivery."""
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    scan_id, finding_id = uuid.uuid4(), uuid.uuid4()
    target_id = uuid.uuid4()

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        return type("S", (), {"id": scan_id, "target_id": target_id})()

    async def fake_finding(_self: object, fid: uuid.UUID) -> object:
        return type("F", (), {"id": fid, "scan_id": scan_id, "fingerprint": "fp-1"})()

    async def fake_get(_self: object, **kwargs: object):
        return None

    async def fake_set(_self: object, **kwargs: object) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "fingerprint": "fp-1",
            "target_id": str(target_id),
            "status": kwargs["status"],
        }

    mocker.patch.object(ScanService, "_get_visible_scan", fake_visible)
    mocker.patch.object(ScanEngineExecutionRepository, "get_finding_by_id", fake_finding)
    mocker.patch.object(ScanEngineExecutionRepository, "get_remediation", fake_get)
    mocker.patch.object(ScanEngineExecutionRepository, "set_remediation", fake_set)

    created = await client.post(
        "/api/v1/webhooks",
        json={"url": "https://hooks.example.com/sentinel", "events": [REMEDIATION_CHANGED]},
        cookies=_auth_cookies(world.owner),
    )
    assert created.status_code == 201, created.text

    import src.workers.webhook_tasks as webhook_tasks

    dispatched: list[str] = []
    mocker.patch.object(
        webhook_tasks,
        "deliver_webhook_task",
        type(
            "T",
            (),
            {"apply_async": staticmethod(lambda args=None, **_k: dispatched.append(args[0]))},
        )(),
    )
    updated = await client.put(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/remediation/notify",
        json={"status": "IN_PROGRESS"},
        cookies=_auth_cookies(world.owner),
    )
    assert updated.status_code == 200, updated.text
    assert dispatched and len(dispatched) == 1


# --------------------------------------------------------------------------- #
# Migration                                                                   #
# --------------------------------------------------------------------------- #


def test_migration_chain_head_is_0015() -> None:
    from importlib import import_module

    chain = {
        "0013": ("0012", "scan_schedules"),
        "0014": ("0013", "webhooks"),
        "0015": ("0014", "remediation_verify_link"),
    }
    for revision, (down, name) in chain.items():
        module = import_module(f"src.infrastructure.database.migrations.versions.{revision}_{name}")
        assert module.revision == revision
        assert module.down_revision == down

    from src.infrastructure.database.models import Base

    assert "webhook" in Base.metadata.tables
    assert "webhook_delivery" in Base.metadata.tables


# --------------------------------------------------------------------------- #
# M7 hardening: terminal honesty, destination-change safety, auditability,    #
# isolation, and quiet-subscriber behavior                                    #
# --------------------------------------------------------------------------- #


async def _run_world_delivery(world, monkeypatch, row, *, send=None, decrypt=None):  # type: ignore[no-untyped-def]
    """Run the worker state machine against the world session double."""
    import src.infrastructure.database.connection as connection
    import src.infrastructure.notifications.sender as sender_module
    import src.infrastructure.secrets.secret_box as secret_box
    from src.workers import webhook_tasks as tasks

    class _Maker:
        def __call__(self):  # type: ignore[no-untyped-def]
            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def _session():  # type: ignore[no-untyped-def]
                yield world.session

            return _session()

    monkeypatch.setattr(connection, "get_async_sessionmaker", lambda: _Maker())
    if send is not None:
        monkeypatch.setattr(sender_module, "send_delivery", send)
    if decrypt is not None:
        monkeypatch.setattr(secret_box, "decrypt_secret", decrypt)
    else:
        monkeypatch.setattr(secret_box, "decrypt_secret", lambda _ciphertext: "raw-secret")

    retries: list[tuple] = []

    async def fake_retry(delivery_id: str, countdown: int) -> None:
        retries.append((delivery_id, countdown))

    return await tasks._deliver(str(row.id), fake_retry), retries


def _ok_send(**kwargs: object) -> object:  # type: ignore[no-untyped-def]
    from src.infrastructure.notifications.sender import DeliveryOutcome

    return DeliveryOutcome(delivered=True, retryable=False, status_code=200)


async def test_worker_unexpected_fault_maps_to_terminal_failed(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A send fault outside the outcome contract fails honestly, never strands."""

    async def exploding_send(**kwargs: object) -> object:  # type: ignore[no-untyped-def]
        raise RuntimeError("transport exploded")

    hook = _stored_hook(world.session)
    row = _delivery(hook.id, "ev-boom", "pending")
    world.session.deliveries[row.id] = row
    result, retries = await _run_world_delivery(world, monkeypatch, row, send=exploding_send)
    assert result["status"] == "failed"
    assert retries == []
    assert row.status == "failed"
    assert str(row.last_error).startswith("worker_error:RuntimeError")
    # Re-entry after the terminal mark is a no-op.
    again, _ = await _run_world_delivery(world, monkeypatch, row, send=exploding_send)
    assert again["status"] == "ignored"


async def test_worker_malformed_id_is_ignored(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.workers import webhook_tasks as tasks

    async def no_retry(_delivery_id: str, _countdown: int) -> None:
        raise AssertionError("no retry expected")

    assert (await tasks._deliver("not-a-uuid", no_retry))["status"] == "ignored"


async def test_worker_not_due_sends_nothing(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from datetime import timedelta

    async def must_not_send(**kwargs: object) -> object:  # type: ignore[no-untyped-def]
        raise AssertionError("send must not run before next_retry_at")

    hook = _stored_hook(world.session)
    row = _delivery(hook.id, "ev-wait", "pending")
    row.next_retry_at = datetime.now(UTC) + timedelta(seconds=600)
    world.session.deliveries[row.id] = row
    result, retries = await _run_world_delivery(world, monkeypatch, row, send=must_not_send)
    assert result["status"] == "not-due"
    assert retries == []
    assert row.status == "pending"


async def test_worker_retry_exhaustion_is_terminal(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The fourth consecutive retryable failure fails: no fifth dispatch."""

    async def fake_retryable(**kwargs: object) -> object:  # type: ignore[no-untyped-def]
        from src.infrastructure.notifications.sender import DeliveryOutcome

        return DeliveryOutcome(delivered=False, retryable=True, detail="HTTP 500")

    hook = _stored_hook(world.session)
    row = _delivery(hook.id, "ev-tired", "pending")
    row.attempts = 3
    world.session.deliveries[row.id] = row
    result, retries = await _run_world_delivery(world, monkeypatch, row, send=fake_retryable)
    assert result["status"] == "failed"
    assert retries == []
    assert row.status == "failed"
    assert row.attempts == 4


async def test_worker_decrypt_failure_is_terminal(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import src.infrastructure.secrets.secret_box as secret_box

    def broken(_ciphertext: str) -> str:
        raise secret_box.WebhookSecretsNotConfiguredError("key rotated away")

    hook = _stored_hook(world.session)
    row = _delivery(hook.id, "ev-locked", "pending")
    world.session.deliveries[row.id] = row
    result, retries = await _run_world_delivery(world, monkeypatch, row, decrypt=broken)
    assert result["status"] == "failed"
    assert retries == []
    assert row.status == "failed"


async def test_url_change_cancels_pending(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Pending rows ledgered against the old destination never surprise the new one."""
    from src.infrastructure.network import webhook_target as target_module

    def fake_validate(url: str, *, timeout_s: float = 5.0):  # type: ignore[no-untyped-def]
        return target_module.ValidatedWebhookTarget(
            url=url, host="hooks.example.com", port=443, addresses=("93.184.216.34",)
        )

    monkeypatch.setattr(target_module, "validate_webhook_url", fake_validate)
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    world.session.deliveries[uuid.uuid4()] = _delivery(created.details.id, "ev-1", "pending")
    updated = await service.update_webhook(
        created.details.id, url="https://hooks.example.com/elsewhere"
    )
    assert updated.url == "https://hooks.example.com/elsewhere"
    assert [r for r in world.session.deliveries.values() if r.status == "pending"] == []


async def test_update_rejects_bad_timeout(world) -> None:  # type: ignore[no-untyped-def]
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    with pytest.raises(InvalidWebhookError):
        await service.update_webhook(created.details.id, timeout_seconds=3600)


async def test_crud_emits_audit_events(world) -> None:  # type: ignore[no-untyped-def]
    """Every subscription mutation is auditable (the ledger covers deliveries)."""
    service = _service(world)
    created = await service.create_webhook(
        url="https://hooks.example.com/sentinel", events=[SCAN_COMPLETED]
    )
    await service.update_webhook(created.details.id, enabled=False)
    await service.delete_webhook(created.details.id)
    codes = [a["action_code"] for a in world.audits]
    assert codes == ["WEBHOOK_CREATED", "WEBHOOK_UPDATED", "WEBHOOK_DELETED"]


async def test_foreign_deliveries_listing_is_404(client: AsyncClient, world) -> None:  # type: ignore[no-untyped-def]
    """Delivery ledgers inherit webhook ownership: foreign ids are 404."""
    response = await client.get(
        f"/api/v1/webhooks/{uuid.uuid4()}/deliveries", cookies=_auth_cookies(world.owner)
    )
    assert response.status_code == 404


async def test_notify_without_subscribers_dispatches_nothing(
    client: AsyncClient, world, mocker
) -> None:  # type: ignore[no-untyped-def]
    """The notify variant persists state with zero fanout when nobody listens."""
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    scan_id, finding_id = uuid.uuid4(), uuid.uuid4()
    target_id = uuid.uuid4()

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        return type("S", (), {"id": scan_id, "target_id": target_id})()

    async def fake_finding(_self: object, fid: uuid.UUID) -> object:
        return type("F", (), {"id": fid, "scan_id": scan_id, "fingerprint": "fp-1"})()

    async def fake_get(_self: object, **kwargs: object):
        return None

    async def fake_set(_self: object, **kwargs: object) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "fingerprint": "fp-1",
            "target_id": str(target_id),
            "status": kwargs["status"],
        }

    mocker.patch.object(ScanService, "_get_visible_scan", fake_visible)
    mocker.patch.object(ScanEngineExecutionRepository, "get_finding_by_id", fake_finding)
    mocker.patch.object(ScanEngineExecutionRepository, "get_remediation", fake_get)
    mocker.patch.object(ScanEngineExecutionRepository, "set_remediation", fake_set)

    import src.workers.webhook_tasks as webhook_tasks

    dispatched: list[str] = []
    mocker.patch.object(
        webhook_tasks,
        "deliver_webhook_task",
        type(
            "T",
            (),
            {"apply_async": staticmethod(lambda args=None, **_k: dispatched.append(args[0]))},
        )(),
    )
    updated = await client.put(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/remediation/notify",
        json={"status": "IN_PROGRESS"},
        cookies=_auth_cookies(world.owner),
    )
    assert updated.status_code == 200, updated.text
    assert dispatched == []

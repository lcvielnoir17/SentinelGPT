"""Regression tests for the single-entry audit-log endpoint (P1-3).

The original ``GET /api/v1/audit-log/{entry_id}`` implementation called
``AuditService.query_entries(limit=200)`` and then searched the returned
list in Python. A valid entry older than the newest 200 was unreachable
and the endpoint incorrectly returned 404.

These tests pin the fixed contract:

* Service: ``AuditService.get_entry`` returns the entry when visible,
  ``None`` when the row is missing or not visible.
* Service: a hidden row is indistinguishable from a missing row (fail-
  closed — no existence leak).
* HTTP: a visible older entry (older than any "newest N" window) is
  retrievable.
* HTTP: a nonexistent entry returns 404.
* HTTP: a real entry belonging to a different user/tenant returns 404,
  not 403.
* HTTP: meta-audit ``AUDIT_LOG_ACCESSED`` is recorded on success.
* HTTP: list endpoint contract is unchanged.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.domain.audit.audit_service import AuditService
from src.infrastructure.database.models import AuditLogEntry

# --------------------------------------------------------------------------- #
# Service-level fixtures                                                       #
# --------------------------------------------------------------------------- #


class _FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _FakeResult:
        return self

    def all(self) -> list[Any]:
        return self._rows

    def first(self):  # type: ignore[no-untyped-def]
        return self._rows[0] if self._rows else None


class _GetSession:
    """Session double that resolves ``session.get(Model, key)`` from
    an in-memory row store and captures inserts (meta-audit)."""

    def __init__(self, rows: dict[uuid.UUID, AuditLogEntry]) -> None:
        self._rows = rows
        self.inserted: list[AuditLogEntry] = []

    def add(self, entry: AuditLogEntry) -> None:
        self.inserted.append(entry)

    async def flush(self) -> None:
        return None

    async def get(self, model: type, key: uuid.UUID) -> Any:
        if model is AuditLogEntry and key in self._rows:
            return self._rows[key]
        return None

    async def execute(self, _stmt: object) -> _FakeResult:
        return _FakeResult([])


def _entry(
    *,
    actor: uuid.UUID | None,
    owner_in_meta: str | None = None,
    action_code: str = "SCAN_REQUESTED",
    entry_id: uuid.UUID | None = None,
) -> AuditLogEntry:
    metadata = {"ownerUserId": owner_in_meta} if owner_in_meta else {}
    return AuditLogEntry(
        id=entry_id or uuid.uuid4(),
        actor_user_id=actor,
        action_code=action_code,
        entity_type="scan",
        entity_id=uuid.uuid4(),
        metadata_json=metadata,
        occurred_at=datetime.now(UTC),
    )


# --------------------------------------------------------------------------- #
# Service-level tests                                                          #
# --------------------------------------------------------------------------- #


async def test_get_entry_returns_visible_entry() -> None:
    """A row whose actor matches the requester is returned."""
    actor = uuid.uuid4()
    row = _entry(actor=actor)
    session = _GetSession({row.id: row})
    service = AuditService(session)  # type: ignore[arg-type]

    result = await service.get_entry(entry_id=row.id, actor_user_id=actor)

    assert result is not None
    assert result.id == row.id
    assert result.actor_user_id == actor


async def test_get_entry_returns_owner_metadata_visible_entry() -> None:
    """A system entry whose metadata ``ownerUserId`` matches the requester
    is visible (mirrors the list-endpoint v1 fail-closed rule)."""
    owner = uuid.uuid4()
    row = _entry(actor=None, owner_in_meta=str(owner))
    session = _GetSession({row.id: row})
    service = AuditService(session)  # type: ignore[arg-type]

    result = await service.get_entry(entry_id=row.id, actor_user_id=owner)

    assert result is not None
    assert result.id == row.id


async def test_get_entry_returns_none_for_missing_row() -> None:
    """A nonexistent id returns ``None`` (caller maps to 404)."""
    session = _GetSession({})
    service = AuditService(session)  # type: ignore[arg-type]

    result = await service.get_entry(
        entry_id=uuid.uuid4(),
        actor_user_id=uuid.uuid4(),
    )

    assert result is None


async def test_get_entry_returns_none_for_cross_tenant_row() -> None:
    """A real entry that does not satisfy ``_visible_to`` is hidden —
    identical behavior to the list endpoint (no existence leak)."""
    other_actor = uuid.uuid4()
    row = _entry(actor=other_actor)
    session = _GetSession({row.id: row})
    service = AuditService(session)  # type: ignore[arg-type]

    result = await service.get_entry(
        entry_id=row.id,
        actor_user_id=uuid.uuid4(),
    )

    assert result is None


async def test_get_entry_records_meta_audit_on_success() -> None:
    """Per SRS Ch5 §12, every successful audit-log access records an
    ``AUDIT_LOG_ACCESSED`` meta-audit event."""
    actor = uuid.uuid4()
    row = _entry(actor=actor, action_code="ATTESTATION_CONFIRMED")
    session = _GetSession({row.id: row})
    service = AuditService(session)  # type: ignore[arg-type]

    await service.get_entry(entry_id=row.id, actor_user_id=actor)

    assert len(session.inserted) == 1
    meta = session.inserted[0]
    assert meta.action_code == "AUDIT_LOG_ACCESSED"
    assert meta.entity_type == "audit_log"
    assert meta.actor_user_id == actor
    assert meta.metadata_json["filters"]["entryId"] == str(row.id)


async def test_get_entry_does_not_record_meta_audit_on_miss() -> None:
    """A failed lookup (hidden or missing) does NOT log access — the
    failed-lookup path is not a successful audit-log access."""
    session = _GetSession({})
    service = AuditService(session)  # type: ignore[arg-type]

    await service.get_entry(
        entry_id=uuid.uuid4(),
        actor_user_id=uuid.uuid4(),
    )

    assert session.inserted == []


# --------------------------------------------------------------------------- #
# HTTP route-level tests                                                       #
# --------------------------------------------------------------------------- #


@pytest.fixture
def client_with_user(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[TestClient, Any]:
    """Spin up the FastAPI app with a stable principal for auth and an
    injected session that resolves audit rows from an in-memory store.
    """
    from src.api.dependencies import get_current_user
    from src.infrastructure.database.connection import get_db_session
    from src.main import create_application

    rows_holder: dict[str, Any] = {"_rows": {}, "_session": None}

    class _HttpFakeSession:
        def __init__(self) -> None:
            self.inserted: list[AuditLogEntry] = []
            self.flushed = 0
            self.query_results: list[list[Any]] = []

        def add(self, entry: AuditLogEntry) -> None:
            self.inserted.append(entry)

        async def flush(self) -> None:
            self.flushed += 1

        async def get(self, model: type, key: uuid.UUID) -> Any:
            rows: dict[uuid.UUID, AuditLogEntry] = rows_holder["_rows"]
            if model is AuditLogEntry and key in rows:
                return rows[key]
            return None

        async def execute(self, _stmt: object) -> _FakeResult:  # noqa: ARG002
            # The audit list endpoint issues `SELECT * FROM audit_log_entry`.
            # Honor any scripted results the test pushed (used by the
            # "list endpoint contract" test) — otherwise return every row
            # currently in the in-memory store.
            if self.query_results:
                return _FakeResult(self.query_results.pop(0))
            rows = list(rows_holder["_rows"].values())
            return _FakeResult(rows)

    async def _override_session() -> Any:
        s = _HttpFakeSession()
        rows_holder["_session"] = s
        return s

    app = create_application()
    app.dependency_overrides[get_db_session] = _override_session

    user = type(
        "U",
        (),
        {
            "id": uuid.uuid4(),
            "email": "audit-tester@example.test",
            "is_active": True,
            "mfa_enabled": False,
        },
    )()
    app.dependency_overrides[get_current_user] = lambda: user

    return TestClient(app), (user, rows_holder)


def _make_row(
    *,
    actor: uuid.UUID | None,
    owner_in_meta: str | None = None,
    action_code: str = "SCAN_REQUESTED",
) -> AuditLogEntry:
    return _entry(actor=actor, owner_in_meta=owner_in_meta, action_code=action_code)


def test_single_entry_endpoint_returns_old_visible_entry(
    client_with_user: tuple[TestClient, Any],
) -> None:
    """The regression proof.

    A visible entry that is intentionally older than any "newest N"
    window must be returned by ``GET /audit-log/{entry_id}``. This test
    would have FAILED on the previous implementation (404), because the
    loop over the newest 200 entries never reached a row outside that
    window.
    """
    client, (user, holder) = client_with_user
    # An old visible row.
    old_row = _make_row(actor=user.id, action_code="ATTESTATION_CONFIRMED")
    # Many newer visible rows that would crowd out the old one if the
    # endpoint still scanned "newest 200".
    for _ in range(250):
        newer = _make_row(actor=user.id)
        holder["_rows"][newer.id] = newer
    holder["_rows"][old_row.id] = old_row

    response = client.get(f"/api/v1/audit-log/{old_row.id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(old_row.id)
    assert body["actionCode"] == "ATTESTATION_CONFIRMED"
    assert body["actorUserId"] == str(user.id)


def test_single_entry_endpoint_returns_404_for_missing_entry(
    client_with_user: tuple[TestClient, Any],
) -> None:
    """A nonexistent id returns the SRS 404 error envelope."""
    client, _holder = client_with_user

    response = client.get(f"/api/v1/audit-log/{uuid.uuid4()}")

    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "NOT_FOUND"
    assert "requestId" in body["error"]


def test_single_entry_endpoint_returns_404_for_cross_tenant_entry(
    client_with_user: tuple[TestClient, Any],
) -> None:
    """A real entry belonging to another user surfaces as 404, not 403.

    This preserves the SRS Ch5 §14 fail-closed rule (no existence leak).
    """
    client, (_user, holder) = client_with_user
    other_actor = uuid.uuid4()
    foreign_row = _make_row(actor=other_actor)
    holder["_rows"][foreign_row.id] = foreign_row

    response = client.get(f"/api/v1/audit-log/{foreign_row.id}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_single_entry_endpoint_records_meta_audit(
    client_with_user: tuple[TestClient, Any],
) -> None:
    """A successful single-entry lookup records AUDIT_LOG_ACCESSED."""
    client, (user, holder) = client_with_user
    row = _make_row(actor=user.id, action_code="SCAN_REQUESTED")
    holder["_rows"][row.id] = row

    response = client.get(f"/api/v1/audit-log/{row.id}")

    assert response.status_code == 200, response.text
    session = holder["_session"]
    assert session is not None
    assert len(session.inserted) == 1
    meta = session.inserted[0]
    assert meta.action_code == "AUDIT_LOG_ACCESSED"
    assert meta.actor_user_id == user.id
    assert meta.metadata_json["filters"]["entryId"] == str(row.id)


def test_list_endpoint_contract_unchanged(
    client_with_user: tuple[TestClient, Any],
) -> None:
    """The fix must not regress the list endpoint contract.

    The list endpoint filters via ``_visible_to``; this test verifies a
    visible row passes through and a foreign row is excluded.
    """
    client, (user, holder) = client_with_user
    own_row = _make_row(actor=user.id, action_code="SCAN_REQUESTED")
    foreign_row = _make_row(actor=uuid.uuid4())
    holder["_rows"][own_row.id] = own_row
    holder["_rows"][foreign_row.id] = foreign_row

    response = client.get("/api/v1/audit-log")

    assert response.status_code == 200, response.text
    body = response.json()
    ids = {row["id"] for row in body}
    assert str(own_row.id) in ids
    assert str(foreign_row.id) not in ids

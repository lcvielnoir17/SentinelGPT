"""Regression tests for system-initiated scan-lifecycle audit visibility.

The original SCAN_STATE_TRANSITION audit entries created during scan
execution recorded ``actor_user_id=None`` (correct: system event per
SRS Ch4 §10.1) but did NOT populate ``metadata.ownerUserId``. Per
``AuditService._visible_to`` that meant the scan initiator — who is
also the v1 scan owner — could not see the lifecycle entries that
describe the scan they own.

This module pins the fixed contract:

* Lifecycle events written by ``scan_service.execute_scan_job`` and
  ``scan_tasks._mark_scan_rejected`` carry ``ownerUserId`` equal to the
  scan's ``initiated_by_user_id``.
* The scan initiator can list and fetch those entries; an unrelated
  user cannot.
* ``SCAN_REQUESTED`` (user-initiated, ``actor_user_id`` set) remains
  visible exactly as before.
* Org/tenant visibility behavior is preserved — a second user in a
  different tenant stays hidden.
* The single-entry ``GET /audit-log/{entry_id}`` continues to surface
  these lifecycle entries to the initiator.
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
# Service-level visibility tests                                              #
# --------------------------------------------------------------------------- #


def _entry(
    *,
    action_code: str,
    actor_user_id: uuid.UUID | None,
    metadata: dict[str, Any],
) -> AuditLogEntry:
    return AuditLogEntry(
        id=uuid.uuid4(),
        actor_user_id=actor_user_id,
        action_code=action_code,
        entity_type="scan",
        entity_id=uuid.uuid4(),
        metadata_json=metadata,
        occurred_at=datetime.now(UTC),
    )


def test_visible_to_returns_true_for_owner_marked_system_entry() -> None:
    """A system event (actor=None) carrying the requester's ``ownerUserId``
    in metadata is visible — this is the v1 fail-closed contract that
    the scan lifecycle events must satisfy.
    """
    initiator = uuid.uuid4()
    row = _entry(
        action_code="SCAN_STATE_TRANSITION",
        actor_user_id=None,
        metadata={
            "from": "RUNNING",
            "to": "EXECUTION_SUCCEEDED",
            "ownerUserId": str(initiator),
        },
    )

    assert AuditService._visible_to(row, initiator) is True


def test_visible_to_returns_false_for_other_user_on_owner_marked_system_entry() -> None:
    """An unrelated user cannot see another user's lifecycle events."""
    initiator = uuid.uuid4()
    other = uuid.uuid4()
    row = _entry(
        action_code="SCAN_STATE_TRANSITION",
        actor_user_id=None,
        metadata={
            "from": "RUNNING",
            "to": "REJECTED",
            "reason": "RuntimeError",
            "ownerUserId": str(initiator),
        },
    )

    assert AuditService._visible_to(row, other) is False


def test_visible_to_returns_false_for_unmarked_system_entry() -> None:
    """A system event WITHOUT ``ownerUserId`` is hidden from all users
    — fail-closed behavior for system events whose owner can't be
    resolved. This is the contract pre-fix; the lifecycle-event sites
    that used to violate this are now corrected.
    """
    initiator = uuid.uuid4()
    row = _entry(
        action_code="SCAN_STATE_TRANSITION",
        actor_user_id=None,
        metadata={"from": "RUNNING", "to": "REJECTED", "reason": "boom"},
    )

    assert AuditService._visible_to(row, initiator) is False


def test_visible_to_returns_true_for_user_initiated_entry() -> None:
    """``SCAN_REQUESTED``-style entries keep working: the actor match is
    unchanged regardless of the metadata-shape fix.
    """
    initiator = uuid.uuid4()
    row = _entry(
        action_code="SCAN_REQUESTED",
        actor_user_id=initiator,
        metadata={
            "targetId": str(uuid.uuid4()),
            "scanProfile": "standard",
            "authorizationAttestationId": str(uuid.uuid4()),
        },
    )

    assert AuditService._visible_to(row, initiator) is True


# --------------------------------------------------------------------------- #
# HTTP route-level regression proof                                             #
# --------------------------------------------------------------------------- #


@pytest.fixture
def client_with_audit_store(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[TestClient, Any]:
    """Spin up the FastAPI app with a stable principal and an injected
    session that:

    * persists added ``AuditLogEntry`` rows on ``session.add``;
    * serves those rows back through ``session.execute(...).scalars().all()``
      so the audit list / single-entry lookups can find them.
    """
    from src.api.dependencies import get_current_user
    from src.infrastructure.database.connection import get_db_session
    from src.main import create_application

    store: dict[str, Any] = {"rows": [], "session": None}

    class _RowResult:
        def __init__(self, rows: list[AuditLogEntry]) -> None:
            self._rows = rows

        def scalars(self) -> _RowResult:
            return self

        def all(self) -> list[AuditLogEntry]:
            return list(self._rows)

        def first(self) -> tuple[Any, ...] | None:
            return (self._rows[0],) if self._rows else None

    class _HttpAuditSession:
        def __init__(self) -> None:
            self.added: list[AuditLogEntry] = []
            self._flushed = 0

        def add(self, entry: AuditLogEntry) -> None:
            self.added.append(entry)
            store["rows"].append(entry)

        async def flush(self) -> None:
            self._flushed += 1

        async def get(self, model: type, key: uuid.UUID) -> Any:
            if model is AuditLogEntry:
                for row in store["rows"]:
                    if row.id == key:
                        return row
            return None

        async def execute(self, _stmt: object) -> _RowResult:
            # Return every audit row currently in the store. The audit
            # list endpoint orders by occurred_at desc internally;
            # query_entries filters by visibility, so order here does
            # not affect the assertion.
            return _RowResult(list(store["rows"]))

    async def _override_session() -> Any:
        s = _HttpAuditSession()
        store["session"] = s
        return s

    app = create_application()
    app.dependency_overrides[get_db_session] = _override_session

    user = type(
        "U",
        (),
        {
            "id": uuid.uuid4(),
            "email": "lifecycle-tester@example.test",
            "is_active": True,
            "mfa_enabled": False,
        },
    )()
    app.dependency_overrides[get_current_user] = lambda: user

    return TestClient(app), (user, store)


def _lifecycle_event(
    *,
    scan_id: uuid.UUID,
    initiator_id: uuid.UUID,
    from_code: str,
    to_code: str,
    reason: str | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> AuditLogEntry:
    """Build a SCAN_STATE_TRANSITION audit row in the post-fix shape."""
    metadata: dict[str, Any] = {
        "from": from_code,
        "to": to_code,
        "ownerUserId": str(initiator_id),
    }
    if reason is not None:
        metadata["reason"] = reason
    return AuditLogEntry(
        id=uuid.uuid4(),
        actor_user_id=actor_user_id,
        action_code="SCAN_STATE_TRANSITION",
        entity_type="scan",
        entity_id=scan_id,
        metadata_json=metadata,
        occurred_at=datetime.now(UTC),
    )


def test_scan_initiator_sees_lifecycle_event_via_list_endpoint(
    client_with_audit_store: tuple[TestClient, Any],
) -> None:
    """The scan initiator can list SCAN_STATE_TRANSITION events."""
    client, (user, store) = client_with_audit_store
    scan_id = uuid.uuid4()
    store["rows"].append(
        _lifecycle_event(
            scan_id=scan_id,
            initiator_id=user.id,
            from_code="RUNNING",
            to_code="EXECUTION_SUCCEEDED",
        )
    )

    response = client.get("/api/v1/audit-log")

    assert response.status_code == 200, response.text
    ids = {row["id"] for row in response.json()}
    assert store["rows"][0].id in {uuid.UUID(v) for v in ids}


def test_scan_initiator_sees_lifecycle_event_via_single_entry_endpoint(
    client_with_audit_store: tuple[TestClient, Any],
) -> None:
    """The single-entry endpoint surfaces the lifecycle event to the
    initiator — this is the direct regression proof for the
    previously-buggy ``GET /audit-log/{entry_id}``.
    """
    client, (user, store) = client_with_audit_store
    scan_id = uuid.uuid4()
    event = _lifecycle_event(
        scan_id=scan_id,
        initiator_id=user.id,
        from_code="QUEUED",
        to_code="REJECTED",
        reason="authorization attestation no longer valid",
    )
    store["rows"].append(event)

    response = client.get(f"/api/v1/audit-log/{event.id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(event.id)
    assert body["actionCode"] == "SCAN_STATE_TRANSITION"
    assert body["actorUserId"] is None
    assert body["metadata"]["ownerUserId"] == str(user.id)


def test_unrelated_user_cannot_see_lifecycle_event(
    client_with_audit_store: tuple[TestClient, Any],
) -> None:
    """A user who did not initiate the scan cannot see its lifecycle
    events via either the list or the single-entry endpoint.
    """
    client, (_user, store) = client_with_audit_store
    other_initiator = uuid.uuid4()
    scan_id = uuid.uuid4()
    event = _lifecycle_event(
        scan_id=scan_id,
        initiator_id=other_initiator,
        from_code="RUNNING",
        to_code="REJECTED",
        reason="worker_crashed:RuntimeError",
    )
    store["rows"].append(event)

    list_response = client.get("/api/v1/audit-log")
    assert list_response.status_code == 200
    assert str(event.id) not in {row["id"] for row in list_response.json()}

    detail_response = client.get(f"/api/v1/audit-log/{event.id}")
    assert detail_response.status_code == 404
    assert detail_response.json()["error"]["code"] == "NOT_FOUND"


def test_scan_requested_event_remains_visible_to_initiator(
    client_with_audit_store: tuple[TestClient, Any],
) -> None:
    """The pre-existing ``SCAN_REQUESTED`` visibility contract (initiator
    sees it; nobody else does) is preserved by the fix.
    """
    client, (user, store) = client_with_audit_store
    requested = AuditLogEntry(
        id=uuid.uuid4(),
        actor_user_id=user.id,
        action_code="SCAN_REQUESTED",
        entity_type="scan",
        entity_id=uuid.uuid4(),
        metadata_json={
            "targetId": str(uuid.uuid4()),
            "scanProfile": "standard",
            "authorizationAttestationId": str(uuid.uuid4()),
        },
        occurred_at=datetime.now(UTC),
    )
    store["rows"].append(requested)

    response = client.get(f"/api/v1/audit-log/{requested.id}")

    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(requested.id)


def test_organization_isolation_preserved_for_lifecycle_events(
    client_with_audit_store: tuple[TestClient, Any],
) -> None:
    """A second user from a different tenant cannot see the lifecycle
    event even when the metadata contains an ``ownerUserId`` for a
    different user. This is the v1 fail-closed isolation baseline.
    """
    client, (_user, store) = client_with_audit_store
    event = _lifecycle_event(
        scan_id=uuid.uuid4(),
        initiator_id=uuid.uuid4(),  # a different initiator
        from_code="RUNNING",
        to_code="EXECUTION_SUCCEEDED",
    )
    store["rows"].append(event)

    response = client.get(f"/api/v1/audit-log/{event.id}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


# --------------------------------------------------------------------------- #
# Direct invocation of the lifecycle emission site                              #
# --------------------------------------------------------------------------- #


async def test_execute_scan_job_emits_owner_metadata_on_state_transitions(
    env: Any,
    mocker: pytest.MonkeyPatch,
) -> None:
    """End-to-end proof: driving a scan to RUNNING → EXECUTION_SUCCEEDED
    via ``execute_scan_job`` produces a SCAN_STATE_TRANSITION entry whose
    metadata records ``ownerUserId`` = the scan's initiator. This is the
    exact metadata the visibility filter reads.
    """
    from src.domain.scanning.findings import Confidence, Severity
    from src.domain.scans.scan_service import ScanService
    from src.scanning.engines.http_analysis import HttpAnalysisResult

    class OkPipeline:
        engine_code = "headers-analyzer"

        def run(self, **_kwargs: object) -> HttpAnalysisResult:
            from src.domain.scanning.findings import Finding

            finding = Finding.create(
                category="http.security-headers",
                title="Missing CSP",
                description="d",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                location="https://seeded.example/",
            )
            return HttpAnalysisResult(
                engine_name="http-security-analysis",
                engine_version="test",
                target_hostname="seeded.example",
                request_scheme="https",
                request_port=443,
                request_path="/",
                status=200,
                redirect_count=0,
                truncated=False,
                content_type="text/html",
                response_bytes=64,
                observations=(),
                findings=(finding,),
                error_kind=None,
                error_detail="",
            )

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)
    initiator_id = env.owner.id

    # Capture audit entries written into the FakeSession during the job.
    captured: list[AuditLogEntry] = []

    real_add = env.session.add

    def capturing_add(obj: object) -> None:
        if isinstance(obj, AuditLogEntry):
            captured.append(obj)
        real_add(obj)

    env.session.add = capturing_add

    await service.execute_scan_job(
        details.id,
        pipeline=OkPipeline(),
        ai_analyzer=None,
    )

    state_transitions = [
        e
        for e in captured
        if isinstance(e, AuditLogEntry)
        and e.action_code == "SCAN_STATE_TRANSITION"
        and e.entity_id == details.id
    ]
    assert state_transitions, "execute_scan_job must record a state transition"
    for entry in state_transitions:
        assert entry.actor_user_id is None, (
            "SCAN_STATE_TRANSITION is a system event per SRS Ch4 §10.1; actor must remain None."
        )
        assert entry.metadata_json.get("ownerUserId") == str(initiator_id), (
            "ownerUserId must be the scan's initiator so the v1 "
            "fail-closed visibility filter surfaces the entry to the owner."
        )

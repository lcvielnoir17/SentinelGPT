"""Unit + integration-style tests for the append-only audit log (ADR-0010).

The database-level immutability trigger is proven against the real Postgres
instance in test_audit_log_db_immutability; scoping/redaction behavior is
proven at service level with a stubbed session.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.domain.audit.audit_service import AuditService
from src.infrastructure.database.models import AuditLogEntry


class FakeResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self):  # type: ignore[no-untyped-def]
        return self

    def all(self):  # type: ignore[no-untyped-def]
        return self._rows

    def first(self):  # type: ignore[no-untyped-def]
        return self._rows[0] if self._rows else None


class FakeSession:
    """Records inserts; replays scripted query results."""

    def __init__(self) -> None:
        self.inserted: list[AuditLogEntry] = []
        self.query_results: list[list] = []

    def add(self, entry: AuditLogEntry) -> None:
        self.inserted.append(entry)

    async def flush(self) -> None:
        pass

    async def execute(self, _stmt: object):
        rows = self.query_results.pop(0) if self.query_results else []
        return FakeResult(rows)


def _entry(actor: uuid.UUID | None, owner_in_meta: str | None = None) -> AuditLogEntry:
    metadata = {"ownerUserId": owner_in_meta} if owner_in_meta else {}
    return AuditLogEntry(
        actor_user_id=actor,
        action_code="SCAN_REQUESTED",
        entity_type="scan",
        entity_id=uuid.uuid4(),
        metadata_json=metadata,
        occurred_at=datetime.now(UTC),
    )


async def test_record_persists_entry_with_metadata() -> None:
    session = FakeSession()
    service = AuditService(session)  # type: ignore[arg-type]
    actor = uuid.uuid4()
    entity_id = uuid.uuid4()

    details = await service.record(
        action_code="ATTESTATION_CONFIRMED",
        entity_type="authorization_attestation",
        entity_id=entity_id,
        metadata_json={"method": "SELF_ATTESTATION"},
        actor_user_id=actor,
    )

    assert len(session.inserted) == 1
    assert details.action_code == "ATTESTATION_CONFIRMED"
    assert details.entity_id == entity_id
    assert session.inserted[0].metadata_json["method"] == "SELF_ATTESTATION"


async def test_query_scopes_to_own_actions_and_owned_entities() -> None:
    user = uuid.uuid4()
    intruder = uuid.uuid4()
    session = FakeSession()
    session.query_results.append(
        [
            _entry(user),  # own action → visible
            _entry(intruder, str(user)),  # owned entity → visible
            _entry(intruder),  # foreign → filtered
        ]
    )
    visible = await AuditService(session).query_entries(actor_user_id=user)
    assert len(visible) == 2


async def test_meta_audit_entry_recorded_for_every_query() -> None:
    session = FakeSession()
    user = uuid.uuid4()
    await AuditService(session).query_entries(actor_user_id=user)

    assert len(session.inserted) == 1
    assert session.inserted[0].action_code == "AUDIT_LOG_ACCESSED"
    assert session.inserted[0].actor_user_id == user


async def test_filters_narrow_results() -> None:
    session = FakeSession()
    user = uuid.uuid4()
    matched = _entry(user)
    session.query_results.append([matched])

    entries = await AuditService(session).query_entries(
        actor_user_id=user,
        entity_type="scan",
        entity_id=matched.entity_id,
        action_code="SCAN_REQUESTED",
        date_from=datetime(2026, 1, 1, tzinfo=UTC),
        date_to=datetime(2027, 1, 1, tzinfo=UTC),
    )
    assert entries[0].id == matched.id


# --------------------------------------------------------------------------- #
# Database-level immutability (real Postgres via the mounted dev database)     #
# --------------------------------------------------------------------------- #


@pytest.mark.integration
async def test_audit_table_rejects_update_and_delete_at_db_level() -> None:
    """Proves the append-only trigger fires for every role, incl. owner."""
    import os

    if not os.environ.get("TEST_DB_IMMUTABILITY"):
        pytest.skip("set TEST_DB_IMMUTABILITY=1 to run the DB trigger proof")

    import sqlalchemy as sa

    from src.infrastructure.database.connection import get_async_engine

    engine = get_async_engine()

    # Create the test row in its own transaction.
    entry_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            sa.text(
                "INSERT INTO audit_log_entry (id, action_code, entity_type, entity_id,"
                " metadata_json) VALUES (:id, 'X', 'test', :eid, '{}')"
            ),
            {"id": entry_id, "eid": uuid.uuid4()},
        )

    # UPDATE must be tested in its own transaction because PostgreSQL
    # aborts the transaction after the trigger raises.
    async with engine.connect() as conn:
        with pytest.raises(Exception, match="append-only"):
            await conn.execute(
                sa.text("UPDATE audit_log_entry SET action_code='Y' WHERE id=:i"),
                {"i": entry_id},
            )

    # DELETE must use a fresh transaction/connection for the same reason.
    async with engine.connect() as conn:
        with pytest.raises(Exception, match="append-only"):
            await conn.execute(
                sa.text("DELETE FROM audit_log_entry WHERE id=:i"),
                {"i": entry_id},
            )
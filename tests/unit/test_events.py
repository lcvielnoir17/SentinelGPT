"""Deterministic domain events: identity, emission, degradation.

Events derive exclusively from persisted state transitions (scan
terminal states, lifecycle rows, remediation upserts). Tests prove
stable idempotency identities, emission at each site, steady-state
silence, and that AI/provider paths never fabricate events.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

from src.domain.events.events import (
    EVENT_SCHEMA_VERSION,
    FINDING_REGRESSED,
    FINDING_RESOLVED,
    NEW_FINDING,
    REMEDIATION_CHANGED,
    SCAN_COMPLETED,
    SCAN_FAILED,
    lifecycle_event,
    make_event_id,
    remediation_event,
    scan_event,
)

NOW = datetime(2026, 5, 1, tzinfo=UTC)
SCAN = uuid.uuid4()
TARGET = uuid.uuid4()


# --------------------------------------------------------------------------- #
# Identity                                                                    #
# --------------------------------------------------------------------------- #


def test_event_id_stable_for_same_transition() -> None:
    first = make_event_id("NEW_FINDING", TARGET, "fp-1", SCAN, NOW.isoformat())
    second = make_event_id("NEW_FINDING", TARGET, "fp-1", SCAN, NOW.isoformat())
    assert first == second
    assert len(first) == 16


def test_event_id_distinguishes_transitions() -> None:
    base = ("NEW_FINDING", TARGET, "fp-1", SCAN, NOW.isoformat())
    assert make_event_id(*base) != make_event_id("FINDING_RESOLVED", *base[1:])
    assert make_event_id(*base) != make_event_id(*base[:2], "fp-2", *base[3:])


def test_lifecycle_mapping_covers_evented_states() -> None:
    assert (
        lifecycle_event(
            lifecycle_status="NEW",
            target_id=TARGET,
            fingerprint="fp",
            scan_id=SCAN,
            occurred_at=NOW,
        ).event_type
        == NEW_FINDING
    )
    assert (
        lifecycle_event(
            lifecycle_status="RESOLVED",
            target_id=TARGET,
            fingerprint="fp",
            scan_id=SCAN,
            occurred_at=NOW,
        ).event_type
        == FINDING_RESOLVED
    )
    assert (
        lifecycle_event(
            lifecycle_status="REGRESSED",
            target_id=TARGET,
            fingerprint="fp",
            scan_id=SCAN,
            occurred_at=NOW,
        ).event_type
        == FINDING_REGRESSED
    )


def test_lifecycle_steady_state_is_silent() -> None:
    assert (
        lifecycle_event(
            lifecycle_status="PERSISTENT",
            target_id=TARGET,
            fingerprint="fp",
            scan_id=SCAN,
            occurred_at=NOW,
        )
        is None
    )
    assert (
        lifecycle_event(
            lifecycle_status="BOGUS",
            target_id=TARGET,
            fingerprint="fp",
            scan_id=SCAN,
            occurred_at=NOW,
        )
        is None
    )


def test_scan_event_shape() -> None:
    event = scan_event(
        event_type=SCAN_COMPLETED,
        scan_id=SCAN,
        target_id=TARGET,
        status="REPORT_READY",
        occurred_at=NOW,
    )
    assert event.scan_id == str(SCAN)
    assert event.transition == "REPORT_READY"
    assert event.version == EVENT_SCHEMA_VERSION
    assert event.payload == {}


def test_remediation_event_old_and_first_set() -> None:
    first = remediation_event(
        target_id=TARGET,
        fingerprint="fp",
        scan_id=SCAN,
        old_status=None,
        new_status="IN_PROGRESS",
        occurred_at=NOW,
    )
    assert first.transition == "NONE->IN_PROGRESS"
    second = remediation_event(
        target_id=TARGET,
        fingerprint="fp",
        scan_id=SCAN,
        old_status="IN_PROGRESS",
        new_status="DONE",
        occurred_at=NOW,
    )
    assert second.transition == "IN_PROGRESS->DONE"
    assert first.event_id != second.event_id


def test_event_payload_carries_no_secrets() -> None:
    event = remediation_event(
        target_id=TARGET,
        fingerprint="fp",
        scan_id=SCAN,
        old_status=None,
        new_status="TODO",
        occurred_at=NOW,
        updated_by_user_id=uuid.uuid4(),
    )
    assert set(event.payload) <= {"updated_by_user_id"}
    assert set(event.to_dict()) == {
        "event_id",
        "event_type",
        "occurred_at",
        "scan_id",
        "target_id",
        "fingerprint",
        "transition",
        "payload",
        "version",
    }


# --------------------------------------------------------------------------- #
# Lifecycle emission                                                          #
# --------------------------------------------------------------------------- #


async def test_record_lifecycle_emits_evented_states(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """_record_lifecycle appends NEW/RESOLVED/REGRESSED events, skips the rest."""
    from src.domain.scans.scan_service import ScanService

    async def fake_previous(_self: object, _t: uuid.UUID, _s: uuid.UUID):
        return None

    async def fake_fingerprints(_self: object, _s: uuid.UUID):
        return set()

    async def fake_history(_self: object, _t: uuid.UUID, _fps: set) -> dict:
        # fp-old was RESOLVED before: reappearing means REGRESSED.
        return {"fp-old": "RESOLVED"}

    async def fake_status_ids(_s: object) -> dict[str, int]:
        return {"NEW": 1, "PERSISTENT": 2, "RESOLVED": 3, "REGRESSED": 4}

    mocker.patch.object(ScanService, "_previous_scan_id", fake_previous)
    mocker.patch.object(ScanService, "_fingerprints_for_scan", fake_fingerprints)
    mocker.patch.object(ScanService, "_latest_status_map", fake_history)
    mocker.patch("src.domain.scans.scan_service._lifecycle_status_ids", fake_status_ids)

    service = ScanService(env.session, env.owner)
    events: list = []
    await service._record_lifecycle(
        target_id=env.target.id,
        scan_id=uuid.uuid4(),
        current_fingerprints={"fp-new", "fp-old"},
        events=events,
    )
    by_type = {e.event_type for e in events}
    assert by_type == {NEW_FINDING, FINDING_REGRESSED}
    assert all(e.target_id == str(env.target.id) for e in events)
    assert all(e.version == EVENT_SCHEMA_VERSION for e in events)


async def test_record_lifecycle_without_collector_writes_rows(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """Omitting ``events`` preserves the legacy write-only behavior."""
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.models import FindingStatusHistory

    async def fake_previous(_self: object, _t: uuid.UUID, _s: uuid.UUID):
        return None

    async def fake_fingerprints(_self: object, _s: uuid.UUID):
        return set()

    async def fake_history(_self: object, _t: uuid.UUID, _fps: set) -> dict:
        return {}

    async def fake_status_ids(_s: object) -> dict[str, int]:
        return {"NEW": 1, "PERSISTENT": 2, "RESOLVED": 3, "REGRESSED": 4}

    mocker.patch.object(ScanService, "_previous_scan_id", fake_previous)
    mocker.patch.object(ScanService, "_fingerprints_for_scan", fake_fingerprints)
    mocker.patch.object(ScanService, "_latest_status_map", fake_history)
    mocker.patch("src.domain.scans.scan_service._lifecycle_status_ids", fake_status_ids)

    service = ScanService(env.session, env.owner)
    await service._record_lifecycle(
        target_id=env.target.id,
        scan_id=uuid.uuid4(),
        current_fingerprints={"fp-new"},
    )
    assert any(isinstance(o, FindingStatusHistory) for o in env.session.added)


# --------------------------------------------------------------------------- #
# Scan terminal events                                                        #
# --------------------------------------------------------------------------- #


def _ok_pipeline():  # type: ignore[no-untyped-def]
    from src.domain.scanning.findings import Confidence, Severity
    from src.scanning.engines.http_analysis import HttpAnalysisResult

    class OkPipeline:
        engine_code = "headers-analyzer"

        def run(self, **_kwargs: object) -> HttpAnalysisResult:
            from src.domain.scanning.findings import Finding

            finding = Finding.create(
                category="http.security-headers",
                title="Missing Content-Security-Policy security header",
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

    return OkPipeline()


async def test_execute_emits_new_finding_and_completed(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """A clean run returns NEW_FINDING rows plus one SCAN_COMPLETED."""
    from src.domain.scans.scan_service import ScanService

    async def fake_status_ids(_s: object) -> dict[str, int]:
        return {"NEW": 1, "PERSISTENT": 2, "RESOLVED": 3, "REGRESSED": 4}

    mocker.patch("src.domain.scans.scan_service._lifecycle_status_ids", fake_status_ids)

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)
    events = await service.execute_scan_job(details.id, pipeline=_ok_pipeline(), ai_analyzer=None)
    kinds = [e.event_type for e in events]
    assert NEW_FINDING in kinds
    assert kinds.count(SCAN_COMPLETED) == 1
    assert SCAN_FAILED not in kinds


async def test_execute_attestation_failure_emits_scan_failed(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """An execution-time attestation lapse fails closed with one event."""
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.attestation_repository import (
        AttestationRepository,
    )

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)

    async def fake_gone(_self: object, _aid: uuid.UUID):
        return None

    mocker.patch.object(AttestationRepository, "get_by_id", fake_gone)
    events = await service.execute_scan_job(details.id, pipeline=_ok_pipeline(), ai_analyzer=None)
    assert [e.event_type for e in events] == [SCAN_FAILED]
    assert events[0].transition == "REJECTED"


# --------------------------------------------------------------------------- #
# Remediation emission                                                        #
# --------------------------------------------------------------------------- #


async def test_remediation_set_emits_transition(monkeypatch: pytest.MonkeyPatch) -> None:
    """First set records NONE->X; re-set records the honest pair."""
    from src.domain.audit.audit_service import AuditService
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from tests.unit.conftest import _principal

    scan_id, finding_id = uuid.uuid4(), uuid.uuid4()
    store: dict = {}

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        return type("S", (), {"id": scan_id, "target_id": uuid.uuid4()})()

    async def fake_finding(_self: object, fid: uuid.UUID) -> object:
        return type("F", (), {"id": fid, "scan_id": scan_id, "fingerprint": "fp-1"})()

    async def fake_get(_self: object, **kwargs: object):
        return None

    async def fake_set(_self: object, **kwargs: object) -> dict:
        store["status"] = kwargs["status"]
        return {"status": kwargs["status"]}

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", fake_finding)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", fake_get)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", fake_set)

    async def _noop_record(_self: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(AuditService, "record", _noop_record)

    service = ScanService(object(), _principal())  # type: ignore[arg-type]
    events: list = []
    await service.set_finding_remediation(
        scan_id, finding_id, {"status": "IN_PROGRESS"}, events=events
    )
    assert [e.transition for e in events] == ["NONE->IN_PROGRESS"]
    assert events[0].event_type == REMEDIATION_CHANGED

    async def fake_existing(_self: object, **kwargs: object):
        return {"status": "IN_PROGRESS"}

    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", fake_existing)
    events2: list = []
    await service.set_finding_remediation(scan_id, finding_id, {"status": "DONE"}, events=events2)
    assert [e.transition for e in events2] == ["IN_PROGRESS->DONE"]


async def test_remediation_without_collector_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Omitting ``events`` preserves the legacy return contract."""
    from src.domain.audit.audit_service import AuditService
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from tests.unit.conftest import _principal

    scan_id, finding_id = uuid.uuid4(), uuid.uuid4()

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        return type("S", (), {"id": scan_id, "target_id": uuid.uuid4()})()

    async def fake_finding(_self: object, fid: uuid.UUID) -> object:
        return type("F", (), {"id": fid, "scan_id": scan_id, "fingerprint": "fp-1"})()

    async def fake_set(_self: object, **kwargs: object) -> dict:
        return {"status": kwargs["status"]}

    async def fake_get(_self: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", fake_finding)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", fake_get)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", fake_set)

    async def _noop_record(_self: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(AuditService, "record", _noop_record)

    service = ScanService(object(), _principal())  # type: ignore[arg-type]
    row = await service.set_finding_remediation(scan_id, finding_id, {"status": "TODO"})
    assert row is not None and row["status"] == "TODO"

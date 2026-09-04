"""Regression tests for the worker's failure-path scan rejection (P1-2).

The original ``_mark_scan_rejected`` required the scan to still be in
QUEUED. A worker failure that occurred after the domain service had
claimed the scan (QUEUED → RUNNING) therefore left the scan stranded in
RUNNING forever: the optimistic transition would not match, no audit
event would be recorded, and no engine-execution row would be marked
FAILED. These tests pin the new contract:

* A scan in RUNNING transitions to REJECTED with the expected audit /
  execution bookkeeping.
* The function is idempotent for an already-terminal scan.
* The original QUEUED → REJECTED behavior is preserved.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest  # noqa: TC002  # pytest runtime for fixtures

from src.config.constants import (
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_REJECTED,
    SCAN_STATUS_RUNNING,
)
from src.workers.scan_tasks import _mark_scan_rejected

SCAN_STATUS_IDS: dict[str, int] = {
    "PENDING_ATTESTATION": 1,
    SCAN_STATUS_QUEUED: 2,
    SCAN_STATUS_RUNNING: 3,
    "PARTIALLY_COMPLETE": 4,
    "SCAN_COMPLETE": 5,
    "AI_ANALYSIS": 6,
    "REPORT_READY": 7,
    "REPORT_READY_DEGRADED": 8,
    SCAN_STATUS_REJECTED: 9,
    "CANCELLED": 10,
}


class _TransitionRepo:
    """In-memory double of ``ScanRepository.try_transition``."""

    def __init__(self, current_status_code: str) -> None:
        self._scan_id = uuid.uuid4()
        self._scan = MagicMock()
        self._scan.id = self._scan_id
        self._scan.status_id = SCAN_STATUS_IDS[current_status_code]
        self.status_codes = dict(SCAN_STATUS_IDS)
        self.attempts: list[tuple[int, int]] = []

    async def status_ids_by_code(self) -> dict[str, int]:
        return self.status_codes

    async def try_transition(
        self,
        scan_id: uuid.UUID,
        *,
        from_status_id: int,
        to_status_id: int,
        set_started_at: Any = None,  # noqa: ARG002
        set_completed_at: Any = None,  # noqa: ARG002
    ) -> bool:
        self.attempts.append((from_status_id, to_status_id))
        if scan_id != self._scan.id:
            return False
        if self._scan.status_id != from_status_id:
            return False
        self._scan.status_id = to_status_id
        return True

    @property
    def scan(self) -> MagicMock:
        return self._scan


class _AuditRecorder:
    """Captures audit calls without touching the database."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def record(self, **kwargs: Any) -> Any:
        self.records.append(kwargs)
        details = MagicMock()
        details.id = uuid.uuid4()
        return details


class _EngineExecRepo:
    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.marked: list[tuple[uuid.UUID, dict[str, Any]]] = []
        self._execution_id = uuid.uuid4()

    async def create(self, **kwargs: Any) -> Any:
        self.created.append(kwargs)
        row = MagicMock()
        row.id = self._execution_id
        return row

    async def mark(self, execution_id: uuid.UUID, **kwargs: Any) -> None:
        self.marked.append((execution_id, kwargs))


class _FakeSession:
    """Async-session double covering the surface _mark_scan_rejected uses."""

    def __init__(self, scan: Any, engine_id: int | None) -> None:
        self._scan = scan
        self._engine_id = engine_id
        self.commits = 0
        self.executed: list[Any] = []

    async def get(self, model: type, key: uuid.UUID) -> Any:
        if model.__name__ == "Scan" and key == self._scan.id:
            return self._scan
        return None

    async def execute(self, stmt: Any) -> MagicMock:
        self.executed.append(stmt)
        result = MagicMock()
        if self._engine_id is None:
            result.first.return_value = None
        else:
            result.first.return_value = (self._engine_id,)
        return result

    async def commit(self) -> None:
        self.commits += 1


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    repo: _TransitionRepo,
    audit: _AuditRecorder,
    execs: _EngineExecRepo,
    engine_id: int | None,
) -> Any:
    """Patch the imports used by ``_mark_scan_rejected``.

    The imports are deferred inside the function, so we patch the real
    module paths instead of ``src.workers.scan_tasks`` attributes. The
    production code calls ``sessionmaker = get_async_sessionmaker()``
    once and then ``async with sessionmaker() as session:`` again, so
    ``get_async_sessionmaker`` must return a factory whose ``__call__``
    returns an async context manager on each invocation (mirroring
    SQLAlchemy ``async_sessionmaker``).
    """

    class _FakeSessionCM:
        async def __aenter__(self) -> _FakeSession:
            return _FakeSession(repo.scan, engine_id)

        async def __aexit__(self, *_exc: object) -> None:
            return None

    class _FakeSessionmaker:
        def __call__(self) -> _FakeSessionCM:
            return _FakeSessionCM()

    def _fake_get_async_sessionmaker() -> _FakeSessionmaker:
        return _FakeSessionmaker()

    monkeypatch.setattr(
        "src.workers.scan_tasks.get_async_sessionmaker",
        _fake_get_async_sessionmaker,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanRepository",
        lambda _s: repo,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository",
        lambda _s: execs,
    )
    monkeypatch.setattr("src.domain.audit.audit_service.AuditService", lambda _s: audit)


async def test_running_scan_transitions_to_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Post-claim worker failures must not strand scans in RUNNING."""
    repo = _TransitionRepo(current_status_code=SCAN_STATUS_RUNNING)
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=42)

    await _mark_scan_rejected(repo.scan.id, "boom")

    # The post-claim transition succeeded.
    assert repo._scan.status_id == SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]
    assert repo.attempts == [
        (SCAN_STATUS_IDS[SCAN_STATUS_RUNNING], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED])
    ]
    # Audit and engine-execution bookkeeping reflect the actual transition.
    assert len(audit.records) == 1
    metadata = audit.records[0]["metadata_json"]
    assert metadata["from"] == SCAN_STATUS_RUNNING
    assert metadata["to"] == SCAN_STATUS_REJECTED
    assert metadata["reason"].startswith("worker_crashed:")
    assert len(execs.created) == 1
    assert len(execs.marked) == 1
    assert execs.marked[0][1]["status"] == "FAILED"


async def test_queued_scan_still_transitions_to_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-claim failure path is preserved: QUEUED scan → REJECTED.

    The implementation now tries RUNNING first (the post-claim case that
    used to strand scans) and falls back to QUEUED. For a scan that is
    still QUEUED, the RUNNING attempt is a benign no-op and the QUEUED
    transition succeeds — preserving the original behavior.
    """
    repo = _TransitionRepo(current_status_code=SCAN_STATUS_QUEUED)
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=42)

    await _mark_scan_rejected(repo.scan.id, "queued-boom")

    assert repo._scan.status_id == SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]
    # RUNNING, SCAN_COMPLETE, PARTIALLY_COMPLETE, AI_ANALYSIS are tried in
    # pipeline order before the QUEUED fallback; the QUEUED attempt succeeds.
    # The audit "from" is the actual source.
    assert repo.attempts == [
        (SCAN_STATUS_IDS[SCAN_STATUS_RUNNING], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS["SCAN_COMPLETE"], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS["PARTIALLY_COMPLETE"], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS["AI_ANALYSIS"], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS[SCAN_STATUS_QUEUED], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
    ]
    assert audit.records[0]["metadata_json"]["from"] == SCAN_STATUS_QUEUED


async def test_already_rejected_scan_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry must NOT clobber audit or engine-execution bookkeeping."""
    repo = _TransitionRepo(current_status_code=SCAN_STATUS_REJECTED)
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=42)

    await _mark_scan_rejected(repo.scan.id, "retry")

    # All five candidates miss, so no spurious audit or execution row.
    assert repo.attempts == [
        (SCAN_STATUS_IDS[SCAN_STATUS_RUNNING], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS["SCAN_COMPLETE"], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS["PARTIALLY_COMPLETE"], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS["AI_ANALYSIS"], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
        (SCAN_STATUS_IDS[SCAN_STATUS_QUEUED], SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]),
    ]
    assert audit.records == []
    assert execs.created == []
    assert execs.marked == []


async def test_already_terminal_report_ready_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful scan must not be overwritten by a late worker retry."""
    repo = _TransitionRepo(current_status_code="REPORT_READY")
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=42)

    await _mark_scan_rejected(repo.scan.id, "late")

    assert repo._scan.status_id == SCAN_STATUS_IDS["REPORT_READY"]
    assert audit.records == []
    assert execs.created == []


async def test_scan_complete_intermediate_is_reaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash between stage commits must not strand SCAN_COMPLETE."""
    repo = _TransitionRepo(current_status_code="SCAN_COMPLETE")
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=42)

    await _mark_scan_rejected(repo.scan.id, "mid-pipeline")

    assert repo._scan.status_id == SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]
    assert audit.records[0]["metadata_json"]["from"] == "SCAN_COMPLETE"
    assert len(execs.created) == 1


async def test_ai_analysis_intermediate_is_reaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash during the AI phase must not strand AI_ANALYSIS."""
    repo = _TransitionRepo(current_status_code="AI_ANALYSIS")
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=42)

    await _mark_scan_rejected(repo.scan.id, "mid-ai")

    assert repo._scan.status_id == SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]
    assert audit.records[0]["metadata_json"]["from"] == "AI_ANALYSIS"


async def test_running_scan_transitions_when_engine_row_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Engine row lookup failure must NOT prevent the REJECTED transition."""
    repo = _TransitionRepo(current_status_code=SCAN_STATUS_RUNNING)
    audit = _AuditRecorder()
    execs = _EngineExecRepo()
    _wire(monkeypatch, repo=repo, audit=audit, execs=execs, engine_id=None)

    await _mark_scan_rejected(repo.scan.id, "no-engine")

    assert repo._scan.status_id == SCAN_STATUS_IDS[SCAN_STATUS_REJECTED]
    assert len(audit.records) == 1
    assert audit.records[0]["metadata_json"]["from"] == SCAN_STATUS_RUNNING
    # No engine row → no engine-execution bookkeeping.
    assert execs.created == []


async def test_missing_scan_is_a_no_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The function must not crash when the scan row is absent."""
    audit = _AuditRecorder()
    execs = _EngineExecRepo()

    class _EmptyGetSession:
        async def __aenter__(self) -> Any:
            inner = _FakeSession(scan=None, engine_id=None)

            async def _get_none(_model: type, _key: uuid.UUID) -> None:
                return None

            inner.get = _get_none  # type: ignore[method-assign,assignment]
            return inner

        async def __aexit__(self, *_exc: object) -> None:
            return None

    class _EmptySessionmaker:
        def __call__(self) -> _EmptyGetSession:
            return _EmptyGetSession()

    def _empty_get() -> _EmptySessionmaker:
        return _EmptySessionmaker()

    monkeypatch.setattr("src.workers.scan_tasks.get_async_sessionmaker", _empty_get)
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanRepository",
        lambda _s: MagicMock(),
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository",
        lambda _s: execs,
    )
    monkeypatch.setattr("src.domain.audit.audit_service.AuditService", lambda _s: audit)
    # Should simply return.
    await _mark_scan_rejected(uuid.uuid4(), "phantom")
    assert audit.records == []
    assert execs.created == []

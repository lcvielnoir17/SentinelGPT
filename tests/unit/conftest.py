"""Shared pytest fixtures for the ``tests/unit`` suite.

The ``env`` fixture in particular builds a complete in-memory fake of
the scan-aggregate dependencies (ScanRepository, ScanEngineExecution-
Repository, TargetRepository, AttestationRepository, MembershipRepository,
plus a FakeSession whose ``.get()`` is wired to the in-memory row stores
so the production ``_resolve_finding_identity`` path can locate
just-created rows). It is the canonical harness for the service-level
security/lifecycle/Phase 9 proofs.
"""

from __future__ import annotations

import types
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from src.infrastructure.database.repositories.attestation_repository import (
    AttestationRepository,
)
from src.infrastructure.database.repositories.membership_repository import (
    MembershipRepository,
)
from src.infrastructure.database.repositories.target_repository import TargetRepository

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from src.domain.users.user_service import UserAccount


STATUS_IDS = {
    "PENDING_ATTESTATION": 1,
    "QUEUED": 2,
    "RUNNING": 3,
    "PARTIALLY_COMPLETE": 4,
    "SCAN_COMPLETE": 5,
    "AI_ANALYSIS": 6,
    "REPORT_READY": 7,
    "REPORT_READY_DEGRADED": 8,
    "REJECTED": 9,
    "CANCELLED": 10,
}


def _principal(uid: uuid.UUID | None = None) -> UserAccount:
    from src.domain.users.user_service import UserAccount

    return UserAccount(id=uid or uuid.uuid4(), email="p@example.com", created_at=datetime.now(UTC))


class FakeSession:
    """Records commits and added objects; never touches a database.

    ``_resolver`` is wired by the ``env`` fixture so ``session.get``
    returns the in-memory row managed by the matching repository double.
    The previous Phase 9 implementation sidestepped this by swallowing
    every exception inside ``_persist_findings``; the cleaner contract is
    that the test double behaves like a real session and the production
    code relies on a real session — no silent fallbacks.
    """

    def __init__(self) -> None:
        self.commits = 0
        self.added: list[object] = []
        self._resolver: Callable[[type, uuid.UUID], Awaitable[object | None]] | None = None

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        return None

    async def get(self, model: type, key: uuid.UUID) -> object | None:  # type: ignore[no-untyped-def]
        if self._resolver is None:
            return None
        return await self._resolver(model, key)

    async def execute(self, _stmt: object) -> None:
        class R:
            def scalars(self):  # type: ignore[no-untyped-def]
                return self

            def all(self):  # type: ignore[no-untyped-def]
                return []

            def first(self):  # type: ignore[no-untyped-def]
                return None

        return R()


class FakeRow:
    """A bare scan row double used by the optimistic-transition test."""

    def __init__(self, *, user_id: uuid.UUID, status_code: str = "QUEUED") -> None:
        self.id = uuid.uuid4()
        self.target_id = uuid.uuid4()
        self.status_code = status_code
        self.status_id = STATUS_IDS[status_code]
        self.scan_profile_code = "standard"
        self.scan_profile_id = 2
        self.initiated_by_user_id = user_id
        self.authorization_attestation_id = uuid.uuid4()
        self.parent_scan_id = None
        now = datetime.now(UTC)
        self.queued_at = now
        self.started_at = None
        self.completed_at = None
        self.created_at = now


class FakeRepo:
    """Repository double implementing the surface ScanService uses."""

    engine_code = "headers-analyzer"
    tool_version_snapshot = "test"

    def __init__(self, session: object = None) -> None:  # noqa: ARG002 - repo signature
        self.rows: dict[uuid.UUID, object] = {}
        self.transitions: list[tuple[int, int]] = []
        self.findings_added = 0
        self.assessments: list[dict] = []

    def add(self, scan: object) -> None:
        self.rows[scan.id] = scan

    async def flush(self) -> None:
        return None

    async def try_transition(
        self,
        scan_id: uuid.UUID,
        *,
        from_status_id: int,
        to_status_id: int,
        set_started_at: object = None,
        set_completed_at: object = None,
    ) -> bool:
        self.transitions.append((from_status_id, to_status_id))
        row = self.rows.get(scan_id)
        if row is None or getattr(row, "status_id", None) != from_status_id:
            return False
        row.status_id = to_status_id
        row.status_code = next(c for c, i in STATUS_IDS.items() if i == to_status_id)
        if set_completed_at is not None:
            row.completed_at = set_completed_at
        if set_started_at is not None:
            row.started_at = set_started_at
        return True

    async def get_by_id(self, scan_id: uuid.UUID) -> object | None:
        return self.rows.get(scan_id)

    async def list_for_user(self, user_id: uuid.UUID, **kwargs: object) -> list:
        rows = [
            r for r in self.rows.values() if getattr(r, "initiated_by_user_id", None) == user_id
        ]
        # Mirror production: newest-first with a limit (default 50).
        rows.sort(key=lambda r: getattr(r, "created_at"), reverse=True)
        limit = kwargs.get("limit", 50)
        assert isinstance(limit, int)
        return rows[:limit]

    async def status_ids_by_code(self) -> dict[str, int]:
        return dict(STATUS_IDS)

    async def status_code_by_id(self) -> dict[int, str]:
        return {i: c for c, i in STATUS_IDS.items()}

    async def profile_code_by_id(self) -> dict[int, str]:
        return {1: "quick-check", 2: "standard", 3: "full-assessment"}


class FakeExecRepo:
    """Repository double for engine-execution persistence."""

    def __init__(self, _s: object) -> None:
        self.findings_added = 0
        self.assessment_calls = 0
        self.executions: dict[uuid.UUID, object] = {}

    async def create(self, **kwargs: object) -> object:
        row = type("R", (), {"id": uuid.uuid4(), **kwargs})()
        self.executions[row.id] = row
        return row

    async def mark(self, *_a: object, **_k: object) -> None:
        pass

    async def add_findings(self, findings: list) -> None:
        self.findings_added += len(findings)

    async def upsert_ai_assessment(self, **kwargs: object) -> None:
        self.assessment_calls += 1
        self.last_assessment = kwargs  # type: ignore[attr-defined]


@pytest.fixture
def env(mocker):  # type: ignore[no-untyped-def]
    """Owner principal + fakes wired into the service module namespace."""
    owner = _principal()
    session = FakeSession()
    env_owner_id = owner.id

    repo = FakeRepo(session)
    mocker.patch(
        "src.infrastructure.database.repositories.scan_repository.ScanRepository",
        lambda _s: repo,  # type: ignore[arg-type,return-value]
    )

    exec_repo = FakeExecRepo(session)
    mocker.patch(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository",
        lambda _s: exec_repo,  # type: ignore[arg-type,return-value]
    )

    from src.infrastructure.database.models import Scan, ScanEngine, ScanEngineExecution

    async def _resolve_session_get(model: type, key: uuid.UUID) -> object | None:
        if model is Scan:
            return repo.rows.get(key)
        if model is ScanEngineExecution:
            return exec_repo.executions.get(key)
        if model is ScanEngine:
            return type("E", (), {"code": "headers-analyzer"})()
        return None

    session._resolver = _resolve_session_get

    target_row = type(
        "T",
        (),
        {
            "id": uuid.uuid4(),
            "hostname": "seeded.example",
            "normalized_url": "https://seeded.example/",
            "owner_user_id": None,
            "owner_organization_id": None,
            "is_archived": False,
            "created_at": datetime.now(UTC),
        },
    )()
    target_row.owner_user_id = env_owner_id

    async def fake_target_get(_self: object, tid: uuid.UUID):
        return target_row if str(tid) == str(target_row.id) else None

    mocker.patch.object(TargetRepository, "get_by_id", fake_target_get)

    attestation = type(
        "A",
        (),
        {
            "id": uuid.uuid4(),
            "status": "CONFIRMED",
            "expires_at": None,
            "method_id": 1,
            "target_id": target_row.id,
            "evidence_file_ref": None,
            "created_by_user_id": None,
            "revoked_at": None,
            "revoked_reason": None,
            "created_at": datetime.now(UTC),
        },
    )()

    async def fake_has_active(_self: object, _tid: uuid.UUID) -> bool:
        return True

    async def fake_latest(_self: object, _tid: uuid.UUID):
        return attestation

    async def fake_att_get_by_id(_self: object, _aid: uuid.UUID):
        return attestation

    async def fake_method_code_map(_self: object) -> dict[int, str]:
        return {1: "SELF_ATTESTATION"}

    mocker.patch.object(AttestationRepository, "has_active_confirmed", fake_has_active)
    mocker.patch.object(AttestationRepository, "latest_active_confirmed", fake_latest)
    mocker.patch.object(AttestationRepository, "get_by_id", fake_att_get_by_id)
    mocker.patch.object(AttestationRepository, "method_code_map", fake_method_code_map)

    async def fake_is_member(_self: object, _u: uuid.UUID, _o: uuid.UUID) -> bool:
        return True

    mocker.patch.object(MembershipRepository, "is_member", fake_is_member)

    async def fake_profile_id(_s: object, code: str) -> int:
        return {"quick-check": 1, "standard": 2, "full-assessment": 3}[code]

    async def fake_status_code(_s: object, sid: int) -> str:
        return next(c for c, i in STATUS_IDS.items() if i == sid)

    async def fake_profile_code(_s: object, pid: int) -> str:
        return {1: "quick-check", 2: "standard", 3: "full-assessment"}[pid]

    mocker.patch(
        "src.infrastructure.database.repositories.scan_repository._profile_id",
        fake_profile_id,
    )
    mocker.patch(
        "src.infrastructure.database.repositories.scan_repository._status_code_of",
        fake_status_code,
    )
    mocker.patch(
        "src.infrastructure.database.repositories.scan_repository._profile_code",
        fake_profile_code,
    )

    async def fake_engine_id(_s: object = None, code: str = "headers-analyzer") -> int:
        return 4

    async def fake_category_ids(_s: object) -> dict[str, int]:
        return {"MISSING_SECURITY_HEADER": 1}

    async def fake_severity_ids(_s: object) -> dict[str, int]:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    mocker.patch("src.domain.scans.scan_service._engine_id", fake_engine_id)
    mocker.patch("src.domain.scans.scan_service._category_ids", fake_category_ids)
    mocker.patch("src.domain.scans.scan_service._severity_ids", fake_severity_ids)
    return types.SimpleNamespace(
        session=session,
        repo=repo,
        exec_repo=exec_repo,
        owner=owner,
        target=target_row,
        attestation=attestation,
    )

"""Security tests for the scan lifecycle service (ADR-0009).

Direct service-level proofs with patched repositories: authorization gate,
tenant isolation, cancellation semantics, optimistic transitions, and
pipeline-failure mapping. The HTTP envelope itself follows the established
target-routes conventions.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest

from src.domain.errors import AttestationNotConfirmedError, NotFoundError
from src.domain.scanning.findings import Confidence, Severity
from src.domain.scans.scan_service import ScanService
from src.domain.users.user_service import UserAccount
from src.infrastructure.database.repositories.attestation_repository import (
    AttestationRepository,
)
from src.infrastructure.database.repositories.membership_repository import (
    MembershipRepository,
)
from src.infrastructure.database.repositories.target_repository import TargetRepository


def _principal(uid: uuid.UUID | None = None) -> UserAccount:
    return UserAccount(id=uid or uuid.uuid4(), email="p@example.com", created_at=datetime.now(UTC))


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


class FakeRow:
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


class FakeSession:
    """Records commits and added objects; never touches a database."""

    def __init__(self) -> None:
        self.commits = 0
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        return None

    async def execute(self, _stmt: object) -> None:
        class R:
            def scalars(self):  # type: ignore[no-untyped-def]
                return self

            def all(self):  # type: ignore[no-untyped-def]
                return []

            def first(self):  # type: ignore[no-untyped-def]
                return None

        return R()


class FakeRepo:
    """Repository double implementing the surface ScanService uses."""

    engine_code = "headers-analyzer"
    tool_version_snapshot = "test"

    def __init__(self, session: object = None) -> None:  # noqa: ARG002 - repo signature
        self.rows: dict[uuid.UUID, object] = {}
        self.transitions: list[tuple[int, int]] = []
        self.findings_added = 0
        self.assessments: list[dict] = []

    # -- writes -------------------------------------------------------------
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

    # -- reads ----------------------------------------------------------------
    async def get_by_id(self, scan_id: uuid.UUID) -> object | None:
        return self.rows.get(scan_id)

    async def list_for_user(self, user_id: uuid.UUID, **_: object) -> list:
        return [
            r for r in self.rows.values() if getattr(r, "initiated_by_user_id", None) == user_id
        ]

    async def status_ids_by_code(self) -> dict[str, int]:
        return dict(STATUS_IDS)


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

    class FakeExecRepo:
        def __init__(self, _s: object) -> None:
            self.findings_added = 0
            self.assessment_calls = 0

        async def create(self, **kwargs: object) -> object:
            return type("R", (), {"id": uuid.uuid4(), **kwargs})()

        async def mark(self, *_a: object, **_k: object) -> None:
            pass

        async def add_findings(self, findings: list) -> None:
            self.findings_added += len(findings)

        async def upsert_ai_assessment(self, **kwargs: object) -> None:
            self.assessment_calls += 1
            self.last_assessment = kwargs  # type: ignore[attr-defined]

    exec_repo = FakeExecRepo(session)
    mocker.patch(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository",
        lambda _s: exec_repo,  # type: ignore[arg-type,return-value]
    )

    # Target visible to owner only.
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

    # Attestation active for the seeded target.
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

    # Real TargetService is used; only its repository is faked above.
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


import types  # noqa: E402

# --------------------------------------------------------------------------- #
# Authorization gate                                                          #
# --------------------------------------------------------------------------- #


async def test_scan_creation_blocked_without_active_attestation(env, mocker) -> None:  # type: ignore[no-untyped-def]
    async def fake_none(_self: object, _tid: uuid.UUID):
        return None

    mocker.patch.object(AttestationRepository, "latest_active_confirmed", fake_none)
    service = ScanService(env.session, env.owner)
    with pytest.raises(AttestationNotConfirmedError):
        await service.create_scan(target_id=env.target.id)


async def test_authorized_creation_queues_scan(env) -> None:  # type: ignore[no-untyped-def]
    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)
    assert details.status_code == "QUEUED"
    assert details.authorization_attestation_id == env.attestation.id


async def test_cross_tenant_user_cannot_create_or_read(env) -> None:  # type: ignore[no-untyped-def]
    intruder = _principal()
    service_intruder = ScanService(env.session, intruder)

    with pytest.raises((NotFoundError, AttestationNotConfirmedError)):
        await service_intruder.create_scan(target_id=env.target.id)

    service_owner = ScanService(env.session, env.owner)
    details = await service_owner.create_scan(target_id=env.target.id)

    with pytest.raises(NotFoundError):
        await service_intruder.get_scan(details.id)
    with pytest.raises(NotFoundError):
        await service_intruder.cancel_scan(details.id)


# --------------------------------------------------------------------------- #
# Execution orchestration                                                     #
# --------------------------------------------------------------------------- #


class OkPipeline:
    engine_code = "headers-analyzer"

    def __init__(self, result: object) -> None:
        self._result = result

    def run(self, **_: object) -> object:
        return self._result


def _analysis_result():  # type: ignore[no-untyped-def]

    from src.domain.scanning.findings import Finding
    from src.scanning.engines.http_analysis import HttpAnalysisResult

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


async def test_successful_job_reaches_report_ready_and_persists(env) -> None:  # type: ignore[no-untyped-def]
    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)

    await service.execute_scan_job(
        details.id,
        pipeline=OkPipeline(_analysis_result()),
        ai_analyzer=None,  # AI unconfigured â†’ degraded, deterministic intact
    )

    row = env.repo.rows[details.id]
    assert row.status_code == "REPORT_READY_DEGRADED"  # AI unavailable path
    assert env.exec_repo.findings_added == 1
    assert env.exec_repo.assessment_calls == 1
    assert env.exec_repo.last_assessment["is_available"] is False


async def test_engine_failure_maps_to_rejected_never_success(env) -> None:  # type: ignore[no-untyped-def]
    class ExplodingPipeline:
        def run(self, **_: object) -> object:
            raise RuntimeError("sandbox detonated")

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)
    await service.execute_scan_job(details.id, pipeline=ExplodingPipeline())

    row = env.repo.rows[details.id]
    assert row.status_code == "REJECTED"
    assert env.exec_repo.findings_added == 0


async def test_revoked_authorization_mid_queue_rejects_scan(env, mocker) -> None:
    """Authorization disappears between QUEUED and RUNNING ⇒ REJECTED."""
    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)

    dead = type(
        "A",
        (),
        {"id": env.attestation.id, "status": "REVOKED", "expires_at": None},
    )()

    async def fake_dead(_self: object, _aid: uuid.UUID):
        return dead

    mocker.patch.object(AttestationRepository, "get_by_id", fake_dead)

    await service.execute_scan_job(details.id, pipeline=OkPipeline(_analysis_result()))

    row = env.repo.rows[details.id]
    assert row.status_code == "REJECTED"
    assert env.exec_repo.findings_added == 0


def test_duplicate_execution_prevented_by_optimistic_transition(env) -> None:
    """Second claimant using the stale from-status loses the race."""
    row = FakeRow(user_id=env.owner.id, status_code="RUNNING")
    env.repo.rows[row.id] = row
    original_status_id = row.status_id

    first = asyncio.run(
        env.repo.try_transition(row.id, from_status_id=original_status_id, to_status_id=9)
    )
    second = asyncio.run(
        env.repo.try_transition(row.id, from_status_id=original_status_id, to_status_id=9)
    )

    assert first is True and second is False


# --------------------------------------------------------------------------- #
# Gate posture                                                                #
# --------------------------------------------------------------------------- #


def test_library_execution_gate_defaults_to_closed() -> None:
    import inspect

    from src.scanning.runner import SandboxedScanExecutor

    signature = inspect.signature(SandboxedScanExecutor.__init__)
    enable_default = signature.parameters["enable_execution"].default
    assert enable_default is False


def test_gate_open_only_inside_composition_root() -> None:
    from pathlib import Path

    pipeline_source = Path("backend/src/domain/scans/pipeline.py").read_text(encoding="utf-8")
    assert "enable_execution=True,  # ADR-0009: gate OPENED only in this file." in pipeline_source

    runner_source = Path("backend/src/scanning/runner.py").read_text(encoding="utf-8")
    import ast

    tree = ast.parse(runner_source)
    opening_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "enable_execution" and "True" in ast.unparse(kw.value)
    ]
    assert opening_calls == [], f"runner gained gate-opening code: {opening_calls}"

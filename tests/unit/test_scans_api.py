"""Security tests for the scan lifecycle service (ADR-0009).

Direct service-level proofs with patched repositories: authorization gate,
tenant isolation, cancellation semantics, optimistic transitions, and
pipeline-failure mapping. The HTTP envelope itself follows the established
target-routes conventions.

The shared in-memory harness (``env`` fixture, ``FakeSession``,
``FakeRepo``, ``FakeExecRepo``, ``STATUS_IDS``, ``FakeRow``) lives in
``tests/unit/conftest.py`` so the Phase 9 rescan/compare tests can
reuse it.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from src.domain.errors import AttestationNotConfirmedError, NotFoundError
from src.domain.scanning.findings import Confidence, Severity
from src.domain.scans.scan_service import ScanService
from src.infrastructure.database.repositories.attestation_repository import (
    AttestationRepository,
)
from tests.unit.conftest import STATUS_IDS, FakeRow, _principal  # noqa: F401 — shared harness

if TYPE_CHECKING:
    import uuid

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
        ai_analyzer=None,
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

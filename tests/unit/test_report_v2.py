"""Reporting 2.0: deterministic, AI-free evidence reports (M5).

The v2 report derives exclusively from stored deterministic evidence
(findings + lifecycle/priority, remediation workflow + M4 verification
states, delta vs previous completed scan, technology inventory, TLS
summary). It contains no AI interpretation, and ``contentHash`` proves
byte-identical renders over unchanged evidence.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import get_settings
from src.domain.errors import NotFoundError
from src.domain.users.token_service import create_access_token
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import User
from src.main import create_application
from src.reporting.assembler import (
    ReportEngineSummary,
    ReportFinding,
    ReportPriority,
    ReportScanMetadata,
)

SETTINGS = get_settings()
NOW = datetime.now(UTC)

TARGET = uuid.uuid4()
SCAN = uuid.uuid4()
PREV = uuid.uuid4()
RESCAN = uuid.uuid4()
FP_A = "fp-report-aaa"
FP_B = "fp-report-bbb"
FP_TLS = "fp-report-tls"


def _user() -> User:
    now = datetime.now(UTC)
    return User(
        id=uuid.uuid4(),
        email="owner@example.com",
        password_hash="x",
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def _scan_row(sid: uuid.UUID, created: datetime) -> object:
    return type("S", (), {"id": sid, "target_id": TARGET, "created_at": created})()


def _finding(
    fid: uuid.UUID,
    fingerprint: str | None,
    severity: str = "HIGH",
    category: str = "MISSING_SECURITY_HEADER",
    lifecycle: str | None = "NEW",
) -> ReportFinding:
    return ReportFinding(
        id=fid,
        severity=severity,
        category=category,
        title=f"title-{fingerprint}",
        description="desc",
        evidence="ev",
        location="/",
        recommendation="fix",
        fingerprint=fingerprint,
        affected_asset=None,
        source_engine_code="headers-analyzer",
        lifecycle_status=lifecycle,
        priority=ReportPriority(
            score=70, level="HIGH", version="SGPT.PRIORITY.V2", factors=("severity",)
        ),
    )


def _base_document(scan_id: uuid.UUID, findings: list[ReportFinding]):  # type: ignore[no-untyped-def]
    from src.reporting.assembler import REPORT_SCHEMA_VERSION, ReportDocument

    severity_counts: dict[str, int] = {}
    lifecycle_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        if finding.lifecycle_status:
            lifecycle_counts[finding.lifecycle_status] = (
                lifecycle_counts.get(finding.lifecycle_status, 0) + 1
            )

    return ReportDocument(
        schema_version=REPORT_SCHEMA_VERSION,
        generated_at=NOW,
        scan=ReportScanMetadata(
            target_hostname="example.com",
            target_normalized_url="https://example.com/",
            scan_id=scan_id,
            scan_profile="standard",
            scan_status="REPORT_READY",
            initiated_by_user_id=uuid.uuid4(),
            queued_at=NOW,
            started_at=NOW,
            completed_at=NOW,
        ),
        engines=(
            ReportEngineSummary(
                engine_code="headers-analyzer",
                tool_version_snapshot="1.0",
                status="SUCCEEDED",
                started_at=NOW,
                completed_at=NOW,
                error_message=None,
            ),
            ReportEngineSummary(
                engine_code="ssl-inspector",
                tool_version_snapshot="1.0",
                status="SUCCEEDED",
                started_at=NOW,
                completed_at=NOW,
                error_message=None,
            ),
        ),
        findings=tuple(findings),
        assessment=None,
        severity_counts=severity_counts,
        lifecycle_counts=lifecycle_counts,
    )


def _details(sid: uuid.UUID, status: str, created: datetime):  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanDetails

    return ScanDetails(
        id=sid,
        target_id=TARGET,
        status_code=status,
        scan_profile_code="standard",
        initiated_by_user_id=uuid.uuid4(),
        authorization_attestation_id=uuid.uuid4(),
        queued_at=None,
        started_at=None,
        completed_at=None,
        created_at=created,
    )


def _patch_common(
    monkeypatch,
    *,
    findings,
    remediations=None,
    technologies=None,  # type: ignore[no-untyped-def]
    candidates=None,
    compare=None,
    rescan_status="REPORT_READY",
):
    """Patch every seam get_scan_report_v2 touches below the tenant gate."""
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )
    from src.reporting.assembler import ReportAssembler

    created = datetime(2026, 5, 1, tzinfo=UTC)

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        if sid == SCAN:
            return _scan_row(SCAN, created)
        if sid == RESCAN:
            stub = _scan_row(RESCAN, created)
            stub.status_code = rescan_status  # type: ignore[attr-defined]
            stub.completed_at = NOW  # type: ignore[attr-defined]
            return stub
        raise NotFoundError()

    async def fake_assemble(_self: object, sid: uuid.UUID):  # type: ignore[no-untyped-def]
        return _base_document(sid, findings)

    async def fake_list(_self: object, **kwargs: object):
        return list(candidates or [])

    async def fake_compare(_self: object, a: uuid.UUID, b: uuid.UUID) -> dict:
        if compare is not None:
            return compare(a, b)
        return {"new": [], "persistent": [], "resolved": [], "regressed": []}

    async def fake_remediations(_self: object, **kwargs: object) -> dict:
        return dict(remediations or {})

    async def fake_technologies(_self: object, target_id: uuid.UUID) -> list:
        return list(technologies or [])

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ReportAssembler, "assemble", fake_assemble)
    monkeypatch.setattr(ScanService, "list_scans", fake_list)
    monkeypatch.setattr(ScanService, "compare_scans", fake_compare)
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_remediations_for_target", fake_remediations
    )
    monkeypatch.setattr(TargetRepository, "list_technologies", fake_technologies)


def _service(principal) -> object:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    return ScanService(object(), principal)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Structure and AI-freedom                                                    #
# --------------------------------------------------------------------------- #


async def test_full_report_structure(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    findings = [
        _finding(uuid.uuid4(), FP_A),
        _finding(uuid.uuid4(), FP_TLS, severity="MEDIUM", category="OUTDATED_TLS"),
    ]
    _patch_common(
        monkeypatch,
        findings=findings,
        technologies=[
            {
                "slug": "nginx",
                "display": "nginx",
                "family": "server",
                "version": "1.25",
                "confidence": "high",
                "observed_in_scan_id": str(SCAN),
                "first_observed_at": NOW.isoformat(),
                "last_observed_at": NOW.isoformat(),
            }
        ],
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    assert report["schemaVersion"] == "sgpt.report.v2"
    assert report["deterministic"] is True
    assert len(str(report["contentHash"])) == 64
    assert report["scan"]["id"] == str(SCAN)
    assert report["scan"]["targetHostname"] == "example.com"
    assert len(report["engines"]) == 2
    assert report["severityCounts"] == {"HIGH": 1, "MEDIUM": 1}
    assert len(report["findings"]) == 2
    assert report["findings"][0]["priority"]["version"] == "SGPT.PRIORITY.V2"
    assert report["findings"][0]["remediation"] is None
    assert report["findings"][0]["verification"] is None
    assert report["technologies"][0]["slug"] == "nginx"
    assert report["tlsSummary"]["findingCount"] == 1
    assert report["tlsSummary"]["byCategory"] == {"OUTDATED_TLS": 1}
    assert report["tlsSummary"]["bySeverity"] == {"MEDIUM": 1}
    assert report["tlsSummary"]["inspectorStatus"] == "SUCCEEDED"
    # Strictly AI-free: no assessment material anywhere in the document.
    blob = json.dumps(report)
    for banned in (
        "assessment",
        "overall_summary",
        "overallSummary",
        "unsupportedClaim",
        "promptSchema",
    ):
        assert banned not in blob


async def test_empty_scan_report(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    _patch_common(monkeypatch, findings=[])
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    assert report["findings"] == []
    assert report["severityCounts"] == {}
    assert report["delta"] is None
    assert report["tlsSummary"]["findingCount"] == 0


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #


async def test_renders_are_byte_identical(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    findings = [_finding(uuid.uuid4(), FP_A)]
    _patch_common(monkeypatch, findings=findings)
    service = _service(principal)
    first = await service.get_scan_report_v2(SCAN)
    second = await service.get_scan_report_v2(SCAN)
    assert first is not None and second is not None
    assert first["contentHash"] == second["contentHash"]
    assert {k: v for k, v in first.items() if k != "generatedAt"} == {
        k: v for k, v in second.items() if k != "generatedAt"
    }


async def test_hash_moves_with_evidence(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    _patch_common(monkeypatch, findings=[_finding(uuid.uuid4(), FP_A)])
    first = await _service(principal).get_scan_report_v2(SCAN)
    changed = _finding(uuid.uuid4(), FP_A)
    _patch_common(
        monkeypatch,
        findings=[
            ReportFinding(
                id=changed.id,
                severity=changed.severity,
                category=changed.category,
                title="title-changed",
                description=changed.description,
                evidence=changed.evidence,
                location=changed.location,
                recommendation=changed.recommendation,
                fingerprint=changed.fingerprint,
                affected_asset=None,
                source_engine_code="headers-analyzer",
                lifecycle_status="NEW",
                priority=changed.priority,
            )
        ],
    )
    second = await _service(principal).get_scan_report_v2(SCAN)
    assert first is not None and second is not None
    assert first["contentHash"] != second["contentHash"]


# --------------------------------------------------------------------------- #
# Delta                                                                       #
# --------------------------------------------------------------------------- #


def _delta_compare(a: uuid.UUID, b: uuid.UUID) -> dict:
    assert (a, b) == (PREV, SCAN)
    return {
        "new": [{"fingerprint": FP_A}],
        "persistent": [{"fingerprint": FP_B}],
        "resolved": [{"fingerprint": "fp-gone"}],
        "regressed": [],
    }


async def test_delta_present(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    findings = [_finding(uuid.uuid4(), FP_A), _finding(uuid.uuid4(), FP_B)]
    earlier = datetime(2026, 4, 1, tzinfo=UTC)
    _patch_common(
        monkeypatch,
        findings=findings,
        candidates=[_details(PREV, "REPORT_READY", earlier)],
        compare=_delta_compare,
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    delta = report["delta"]
    assert delta is not None
    assert delta["previousScanId"] == str(PREV)
    assert delta["counts"] == {"new": 1, "persistent": 1, "resolved": 1, "regressed": 0}
    assert delta["fingerprints"]["new"] == [FP_A]
    assert delta["fingerprints"]["resolved"] == ["fp-gone"]


async def test_delta_absent_on_first_scan(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    _patch_common(monkeypatch, findings=[_finding(uuid.uuid4(), FP_A)], candidates=[])
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None and report["delta"] is None


async def test_delta_skips_incomplete_scans(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    earlier = datetime(2026, 4, 1, tzinfo=UTC)
    _patch_common(
        monkeypatch,
        findings=[_finding(uuid.uuid4(), FP_A)],
        candidates=[_details(PREV, "RUNNING", earlier)],
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None and report["delta"] is None


async def test_delta_picks_latest_completed(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    old = _details(uuid.uuid4(), "REPORT_READY", datetime(2026, 3, 1, tzinfo=UTC))
    new = _details(uuid.uuid4(), "REPORT_READY_DEGRADED", datetime(2026, 4, 15, tzinfo=UTC))

    seen: list = []

    def _compare(a: uuid.UUID, b: uuid.UUID) -> dict:
        seen.append(a)
        return {"new": [], "persistent": [], "resolved": [], "regressed": []}

    _patch_common(monkeypatch, findings=[], candidates=[old, new], compare=_compare)
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    assert report["delta"] is not None
    assert report["delta"]["previousScanId"] == str(new.id)
    assert seen == [new.id]


# --------------------------------------------------------------------------- #
# Remediation + verification                                                  #
# --------------------------------------------------------------------------- #


def _remediation_row(status: str, rescan: uuid.UUID | None = None) -> dict:
    return {
        "status": status,
        "notes": "patching",
        "updated_at": NOW.isoformat(),
        "verified_in_scan_id": str(rescan) if rescan else None,
    }


async def test_remediation_and_verification_states(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    findings = [_finding(uuid.uuid4(), FP_A), _finding(uuid.uuid4(), FP_B)]

    def _compare(a: uuid.UUID, b: uuid.UUID) -> dict:
        if b == RESCAN:
            return {
                "new": [],
                "persistent": [{"fingerprint": FP_B}],
                "resolved": [{"fingerprint": FP_A}],
                "regressed": [],
            }
        raise AssertionError("no delta expected")

    _patch_common(
        monkeypatch,
        findings=findings,
        remediations={
            FP_A: _remediation_row("DONE", RESCAN),
            FP_B: _remediation_row("IN_PROGRESS", RESCAN),
        },
        compare=_compare,
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    by_fp = {f["fingerprint"]: f for f in report["findings"]}
    assert by_fp[FP_A]["remediation"]["status"] == "DONE"
    assert by_fp[FP_A]["verification"]["state"] == "verified_fixed"
    assert by_fp[FP_A]["verification"]["rescanId"] == str(RESCAN)
    assert by_fp[FP_B]["verification"]["state"] == "still_present"


async def test_verification_pending_while_running(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    _patch_common(
        monkeypatch,
        findings=[_finding(uuid.uuid4(), FP_A)],
        remediations={FP_A: _remediation_row("DONE", RESCAN)},
        rescan_status="RUNNING",
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    assert report["findings"][0]["verification"]["state"] == "pending"


async def test_verification_stale_on_rejected(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    _patch_common(
        monkeypatch,
        findings=[_finding(uuid.uuid4(), FP_A)],
        remediations={FP_A: _remediation_row("DONE", RESCAN)},
        rescan_status="REJECTED",
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    assert report["findings"][0]["verification"]["state"] == "stale"


async def test_verification_stale_on_dangling_link(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    ghost = uuid.uuid4()
    _patch_common(
        monkeypatch,
        findings=[_finding(uuid.uuid4(), FP_A)],
        remediations={FP_A: _remediation_row("DONE", ghost)},
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    verification = report["findings"][0]["verification"]
    assert verification is not None and verification["state"] == "stale"


async def test_shared_rescan_compares_once(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    findings = [_finding(uuid.uuid4(), FP_A), _finding(uuid.uuid4(), FP_B)]
    calls: list = []

    def _compare(a: uuid.UUID, b: uuid.UUID) -> dict:
        calls.append((a, b))
        return {"new": [], "persistent": [], "resolved": [], "regressed": []}

    _patch_common(
        monkeypatch,
        findings=findings,
        remediations={
            FP_A: _remediation_row("DONE", RESCAN),
            FP_B: _remediation_row("DONE", RESCAN),
        },
        compare=_compare,
    )
    report = await _service(principal).get_scan_report_v2(SCAN)
    assert report is not None
    assert calls == [(SCAN, RESCAN)]


# --------------------------------------------------------------------------- #
# Tenancy                                                                     #
# --------------------------------------------------------------------------- #


async def test_invisible_scan_raises(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    async def fake_denied(_self: object, sid: uuid.UUID) -> object:
        raise NotFoundError()

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_denied)
    with pytest.raises(NotFoundError):
        await _service(principal).get_scan_report_v2(uuid.uuid4())


async def test_missing_base_returns_none(monkeypatch, principal) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService
    from src.reporting.assembler import ReportAssembler

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        return _scan_row(SCAN, datetime(2026, 5, 1, tzinfo=UTC))

    async def fake_missing(_self: object, sid: uuid.UUID):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ReportAssembler, "assemble", fake_missing)
    assert await _service(principal).get_scan_report_v2(SCAN) is None


# --------------------------------------------------------------------------- #
# HTTP envelope                                                               #
# --------------------------------------------------------------------------- #


@pytest.fixture
def principal() -> User:
    return _user()


@pytest.fixture
async def client(monkeypatch, principal):  # type: ignore[no-untyped-def]
    from src.infrastructure.database.repositories.user_repository import UserRepository

    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield object()

    application.dependency_overrides[get_db_session] = _overridden_session

    async def fake_get_by_user_id(_self: object, user_id: uuid.UUID):  # type: ignore[no-untyped-def]
        return principal if user_id == principal.id else None

    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_user_id)
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


async def test_route_report_v2(client: AsyncClient, principal, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_common(
        monkeypatch,
        findings=[_finding(uuid.uuid4(), FP_A)],
        remediations={FP_A: _remediation_row("IN_PROGRESS")},
    )
    response = await client.get(f"/api/v1/scans/{SCAN}/report/v2", cookies=_auth_cookies(principal))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schemaVersion"] == "sgpt.report.v2"
    assert body["deterministic"] is True
    assert len(body["contentHash"]) == 64
    assert body["findings"][0]["remediation"]["status"] == "IN_PROGRESS"
    assert body["findings"][0]["verification"] is None
    assert body["delta"] is None


async def test_route_report_v2_unknown_scan(client: AsyncClient, principal, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.scans.scan_service import ScanService

    async def fake_denied(_self: object, sid: uuid.UUID) -> object:
        raise NotFoundError()

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_denied)
    response = await client.get(
        f"/api/v1/scans/{uuid.uuid4()}/report/v2", cookies=_auth_cookies(principal)
    )
    assert response.status_code == 404

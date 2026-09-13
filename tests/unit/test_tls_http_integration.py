"""TLS/HTTP composition: composite engine, per-engine persistence, transport.

Proves the merge seam: one sandbox attempt can carry two engines while
each engine's findings persist under its own execution row (exact
``source_engine_code``), plus the workload→transport TLS contract.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import uuid

from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.findings import Confidence, Finding, Severity
from src.domain.scanning.http_contract import HttpLimits, ScanCancellation
from src.scanning.engines.combined import CompositeEngine
from src.scanning.engines.services import EngineServices, OriginSpec

PIN = "93.184.216.34"


def _context() -> ScanNetworkContext:
    binding = ValidatedTargetBinding.create(
        hostname="target.example",
        addresses=(ipaddress.ip_address(PIN),),
        validate=lambda _a: None,
    ).with_pinned(ipaddress.ip_address(PIN))
    return ScanNetworkContext.create(binding)


def _services() -> EngineServices:
    return EngineServices(
        http_client_factory=lambda: None,  # type: ignore[return-value]
        cancellation=ScanCancellation.create(),
        limits=HttpLimits(),
        origin=OriginSpec(scheme="https", path="/"),
        _context=_context(),
    )


def _finding(category: str, title: str, severity: Severity) -> Finding:
    return Finding.create(
        category=category,
        title=title,
        description="d",
        severity=severity,
        confidence=Confidence.HIGH,
        evidence="e",
        location="https://target.example/",
        recommendation="r",
    )


class _StubEngine:
    def __init__(self, name: str, findings: list[Finding]) -> None:
        self.name = name
        self._findings = findings

    def execute(self, context, services):  # noqa: ARG002 - stub shape
        from src.domain.scanning.findings import Observation

        return type(
            "R",
            (),
            {
                "findings": tuple(self._findings),
                "observations": (
                    Observation.create(category="x", title=f"{self.name} saw", detail="d"),
                ),
            },
        )()


def test_composite_merges_with_attribution() -> None:
    http_finding = _finding("http.cookies", "Cookies without the Secure attribute", Severity.LOW)
    tls_finding = _finding("tls.certificate", "TLS certificate expired", Severity.MEDIUM)
    engine = CompositeEngine(
        primary=_StubEngine("http", [http_finding]),
        secondary=_StubEngine("tls", [tls_finding]),
        primary_code="headers-analyzer",
        primary_version="1",
        secondary_code="ssl-inspector",
        secondary_version="1",
    )
    result = engine.execute(_context(), _services())
    assert [f.title for f in result.findings] == [
        "Cookies without the Secure attribute",
        "TLS certificate expired",
    ]
    assert len(result.observations) == 2
    assert result.engine_code == "headers-analyzer"
    assert [code for code, _ver, _f in result.engine_results] == [
        "headers-analyzer",
        "ssl-inspector",
    ]
    assert [len(f) for _, _, f in result.engine_results] == [1, 1]


def test_composite_without_secondary_is_single_engine() -> None:
    engine = CompositeEngine(
        primary=_StubEngine("http", []),
        primary_code="headers-analyzer",
        primary_version="1",
    )
    result = engine.execute(_context(), _services())
    assert result.findings == ()
    assert len(result.engine_results) == 1


def test_composite_result_feeds_evidence_set() -> None:
    """Regression: https scans crashed at the AI stage because the merged
    result lacked the request envelope EvidenceSet requires."""
    from src.domain.scanning.analysis.evidence import EvidenceSet

    http_finding = _finding("http.cookies", "Cookies without the Secure attribute", Severity.LOW)
    tls_finding = _finding("tls.certificate", "TLS certificate expired", Severity.MEDIUM)
    engine = CompositeEngine(
        primary=_StubEngine("http", [http_finding]),
        secondary=_StubEngine("tls", [tls_finding]),
        primary_code="headers-analyzer",
        primary_version="1",
        secondary_code="ssl-inspector",
        secondary_version="1",
    )
    result = engine.execute(_context(), _services())
    evidence = EvidenceSet.from_result(result)
    assert evidence.finding_ids and len(evidence.finding_ids) == 2
    assert evidence.target_hostname == "target.example"
    assert len(evidence.observations) == 2


def test_tls_category_mapping() -> None:
    from src.domain.scans.scan_service import _canonical_category_code

    assert _canonical_category_code("tls.certificate") == "OUTDATED_TLS"
    assert _canonical_category_code("tls.protocol") == "OUTDATED_TLS"
    assert _canonical_category_code("tls.cipher") == "WEAK_CIPHER"


async def test_extra_engine_findings_persist_under_own_execution(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """Composite breakdown → one execution row per engine, exact codes."""
    import types

    from src.domain.scans.scan_service import ScanService

    service = ScanService(env.session, env.owner)
    http_finding = _finding("http.cookies", "Cookies without the Secure attribute", Severity.LOW)
    tls_finding = _finding("tls.certificate", "TLS certificate expired", Severity.MEDIUM)
    analysis = types.SimpleNamespace(
        findings=(http_finding, tls_finding),
        engine_results=(
            ("headers-analyzer", "1", (http_finding,)),
            ("ssl-inspector", "1", (tls_finding,)),
        ),
    )

    created: list[dict] = []
    persisted: list[object] = []
    real_create = env.exec_repo.create

    async def spy_create(**kwargs):  # type: ignore[no-untyped-def]
        created.append(kwargs)
        return await real_create(**kwargs)

    mocker.patch.object(env.exec_repo, "create", spy_create)

    real_add = env.exec_repo.add_findings

    async def spy_add(findings: list) -> None:
        persisted.extend(findings)
        await real_add(findings)

    mocker.patch.object(env.exec_repo, "add_findings", spy_add)

    scan = type("S", (), {"id": uuid.uuid4(), "target_id": env.target.id})()
    env.repo.rows[scan.id] = scan
    await service._persist_extra_engine_findings(env.exec_repo, scan, analysis)

    assert len(created) == 1  # primary persists under the pre-created row
    assert created[0]["scan_engine_id"] == 4  # env fake maps ssl-inspector → 4
    assert env.exec_repo.findings_added == 1
    # The TLS finding carries a stable fingerprint and canonical category,
    # so lifecycle/comparison/priority work with zero extra wiring.
    (row,) = persisted
    assert row.fingerprint
    from src.domain.scans.fingerprinting import generate_fingerprint_from_finding

    assert row.fingerprint == generate_fingerprint_from_finding(
        hostname="seeded.example",
        category_code="OUTDATED_TLS",
        title="TLS certificate expired",
        location="https://target.example/",
    )


def test_workload_tls_payload_contract() -> None:
    """Transport parses the workload TLS block; errors carry TLS state."""
    from src.domain.scanning.http_contract import (
        ConnectionTarget,
        ControlledTransportError,
        TransportFailureKind,
    )
    from src.scanning.sandbox.base import ExecResult
    from src.scanning.sandbox.http_transport import _parse_exec_result

    target = ConnectionTarget(
        address=ipaddress.ip_address(PIN), port=443, scheme="https", hostname="h.test"
    )
    tls_block = {
        "version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
        "verified": True,
        "verify_error": None,
        "certificate": {
            "subject": "CN=h.test",
            "issuer": "CN=CA",
            "san": ["h.test"],
            "not_before": "Jan  1 00:00:00 2020 GMT",
            "not_after": "Jan  1 00:00:00 2030 GMT",
        },
    }
    payload = {
        "status": 200,
        "headers": [["content-type", "text/html"]],
        "body_b64": base64.b64encode(b"ok").decode(),
        "truncated": False,
        "elapsed_ms": 3.0,
        "tls": tls_block,
    }
    result = ExecResult(
        argv=(), duration_s=0.0, stdout=f"SGPT/1 {json.dumps(payload)}\n", stderr="", exit_code=0
    )
    parsed = _parse_exec_result(result, final_target=target)
    assert parsed.tls is not None
    assert parsed.tls.version == "TLSv1.3"
    assert parsed.tls.certificate is not None
    assert parsed.tls.certificate.san == ("h.test",)

    err_payload = {
        "kind": "tls_error",
        "detail": "certificate verification failed",
        "tls": tls_block,
    }
    err_result = ExecResult(
        argv=(),
        duration_s=0.0,
        stdout=f"SGPTERR/1 {json.dumps(err_payload)}\n",
        stderr="",
        exit_code=2,
    )
    try:
        _parse_exec_result(err_result, final_target=target)
        raise AssertionError("expected ControlledTransportError")
    except ControlledTransportError as exc:
        assert exc.kind == TransportFailureKind.TLS_ERROR
        assert exc.tls is not None
        assert exc.tls.verified is True

    # Malformed TLS blocks degrade to None, never raise.
    bad = dict(payload, tls={"version": 123, "certificate": "nope"})
    bad_result = ExecResult(
        argv=(), duration_s=0.0, stdout=f"SGPT/1 {json.dumps(bad)}\n", stderr="", exit_code=0
    )
    assert _parse_exec_result(bad_result, final_target=target).tls is None


def test_workload_pure_helpers() -> None:
    from src.scanning.sandbox import http_workload as workload

    assert workload._spec_scheme({"url": "https://1.2.3.4:443/"}) == "https"
    assert workload._spec_host_port({"url": "https://1.2.3.4:8443/x"}) == ("1.2.3.4", 8443)
    assert workload._spec_host_port({"url": "https://1.2.3.4/"}) == ("1.2.3.4", 443)
    assert workload._spec_host_port({"url": "not a url"}) is None
    # Non-https and missing SNI never attempt a handshake.
    assert workload._describe_tls({"url": "http://1.2.3.4/"}, verify=True) is None
    assert (
        workload._describe_tls(
            {"url": "https://1.2.3.4/", "sni_hostname": "", "connect_timeout_s": 1.0},
            verify=True,
        )
        is None
    )
    cert = {
        "subject": (
            (
                ("CN", "h.test"),
                ("O", "Ex"),
            ),
        ),
        "issuer": ((("CN", "CA"),),),
        "subjectAltName": (("DNS", "h.test"), ("IP Address", "1.2.3.4"), ("other", "x")),
        "notBefore": "Jan  1 00:00:00 2020 GMT",
        "notAfter": "Jan  1 00:00:00 2030 GMT",
    }
    flat = workload._cert_to_jsonable(cert)
    assert flat["subject"] == "CN=h.test,O=Ex"
    assert flat["san"] == ["h.test", "1.2.3.4"]
    assert flat["not_after"] == "Jan  1 00:00:00 2030 GMT"

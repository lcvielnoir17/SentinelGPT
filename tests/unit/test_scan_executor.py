"""Unit tests for the gated scan execution chain (Part E)."""

from __future__ import annotations

import ipaddress

import pytest

from src.domain.errors import (
    SandboxUnavailableError,
    ScannerExecutionBlockedError,
)
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.resolution import ScanTargetResolutionService
from src.scanning.runner import SandboxAwareEngine, SandboxedScanExecutor
from src.scanning.sandbox.base import ExecResult, SandboxVerification, require_established
from src.scanning.sandbox.policy import SandboxEgressPolicy
from tests.unit.test_resolution_binding import FakeResolver

AUTH_IP = "93.184.216.34"


class ScriptedSandbox:
    """Fake sandbox recording the exact call order around the gate."""

    def __init__(self, policy: SandboxEgressPolicy, *, fail_establish: bool = False) -> None:
        self.policy = policy
        self.fail_establish = fail_establish
        self.events: list[str] = []
        self._established = False

    @property
    def established(self) -> bool:
        return self._established

    def establish(self) -> SandboxVerification:
        self.events.append("establish")
        if self.fail_establish:
            raise SandboxUnavailableError("scripted failure")
        self._established = True
        return SandboxVerification(
            rule_dump=("-P OUTPUT DROP",),
            default_drop=True,
            allowed_addresses=frozenset(self.policy.allowed_addresses),
        )

    def verify(self) -> SandboxVerification:
        require_established(self)
        return SandboxVerification(
            rule_dump=("-P OUTPUT DROP",),
            default_drop=True,
            allowed_addresses=frozenset(self.policy.allowed_addresses),
        )

    def run(self, argv: list[str]) -> ExecResult:
        self.events.append(f"run:{argv}")
        return ExecResult(argv=tuple(argv), exit_code=0, stdout="", stderr="", duration_s=0.0)

    def destroy(self) -> None:
        self.events.append("destroy")
        self._established = False


def _executor(*, fail_establish: bool = False, enable_execution: bool = True):
    resolver = FakeResolver({"target.example": FakeResolver.records(AUTH_IP)})
    made: list[ScriptedSandbox] = []

    def factory(policy: SandboxEgressPolicy) -> ScriptedSandbox:
        sandbox = ScriptedSandbox(policy, fail_establish=fail_establish)
        made.append(sandbox)
        return sandbox

    executor = SandboxedScanExecutor(
        ScanTargetResolutionService(resolver),  # type: ignore[arg-type]
        factory,  # type: ignore[arg-type]
        enable_execution=enable_execution,
    )
    return executor, made


def test_execution_still_blocked_by_default_even_with_engine() -> None:
    """Gate default is CLOSED even when a real engine instance is passed."""
    engine = RecordingEngine()
    executor, made = _executor(enable_execution=False)
    with pytest.raises(ScannerExecutionBlockedError):
        executor.execute_scan("target.example", engine=engine)  # type: ignore[arg-type]
    (sandbox,) = made
    assert sandbox.events == ["establish", "destroy"]

    hardened_default = SandboxedScanExecutor(
        ScanTargetResolutionService(FakeResolver({})),  # type: ignore[arg-type]
        lambda _policy: None,  # type: ignore[arg-type,return-value]
    )
    assert hardened_default._enable_execution is False  # noqa: SLF001 - wiring


def test_execution_blocked_without_engine_when_enabled() -> None:
    """enable_execution=True still requires a concrete engine instance."""
    executor, _ = _executor(enable_execution=True)
    with pytest.raises(ScannerExecutionBlockedError):
        executor.execute_scan("target.example")


def test_chain_order_is_bind_then_establish_then_gate_then_destroy() -> None:
    executor, made = _executor()
    with pytest.raises(ScannerExecutionBlockedError):
        executor.execute_scan("target.example", target_id=None)
    (sandbox,) = made
    assert sandbox.events == ["establish", "destroy"]


def test_factory_receives_binding_derived_policy_only() -> None:
    executor, made = _executor()
    with pytest.raises(ScannerExecutionBlockedError):
        executor.execute_scan("target.example")

    (sandbox,) = made
    assert isinstance(sandbox.policy, SandboxEgressPolicy)
    assert [str(a) for a in sandbox.policy.allowed_addresses] == [AUTH_IP]


def test_establishment_failure_propagates_and_skips_engine_gate() -> None:
    executor, _made = _executor(fail_establish=True)
    with pytest.raises(SandboxUnavailableError):
        executor.execute_scan("target.example")


class RecordingEngine:
    name = "recording"

    def __init__(self) -> None:
        self.calls: list[tuple[object, object]] = []

    def execute(self, context, services) -> None:  # type: ignore[no-untyped-def]
        self.calls.append((context, services))


def test_engine_runs_inside_established_sandbox_and_cleanup_happens() -> None:
    engine = RecordingEngine()
    executor, made = _executor()
    # Bypass ONLY the no-engine invariant to observe the contract a real
    # engine will receive; every security step still runs.
    executor.execute_scan("target.example", engine=engine)  # type: ignore[arg-type]

    (sandbox,) = made
    assert sandbox.events[-1] == "destroy"
    assert sandbox.events.count("establish") == 1

    (context, services) = engine.calls[0]
    assert [str(a) for a in context.binding.addresses] == [AUTH_IP]  # type: ignore[attr-defined]
    # Services are bound to THIS context and start uncancelled.
    assert services.context is context  # type: ignore[attr-defined]
    assert services.cancellation.cancelled is False  # type: ignore[attr-defined]
    assert services.limits.max_redirects == 10  # type: ignore[attr-defined]


def test_engine_receives_pinned_binding_for_first_logical_request() -> None:
    """Regression: ConnectionTarget.for_context refuses an unpinned binding.

    The production pipeline (``DefaultScanPipeline.run``) drives
    ``executor.execute_scan(...)`` which must hand the engine a context whose
    binding has its primary address pinned; otherwise the first
    ``ConnectionTarget.for_context`` call raises EgressDeniedError and the
    scan rejects despite an established sandbox.
    """
    engine = RecordingEngine()
    executor, _ = _executor()
    executor.execute_scan("target.example", engine=engine)  # type: ignore[arg-type]

    (context, _services) = engine.calls[0]
    assert context.binding.pinned_address is not None  # type: ignore[attr-defined]
    assert context.binding.pinned_address == context.binding.addresses[0]  # type: ignore[attr-defined]


def test_engine_services_http_transport_is_real_and_fail_closed() -> None:
    """Phase 4: the factory yields the sandbox-bound transport, which
    refuses to operate once the attempt's sandbox has been torn down."""
    import ipaddress

    from src.domain.errors import SandboxNotEstablishedError
    from src.domain.scanning.http_contract import (
        HttpLimits,
        HttpRequestSpec,
        HttpScanRequest,
        ScanCancellation,
    )
    from src.scanning.sandbox.http_transport import SandboxHttpClient

    engine = RecordingEngine()
    executor, made = _executor()
    executor.execute_scan("target.example", engine=engine)  # type: ignore[arg-type]

    (context, services) = engine.calls[0]
    client = services.http_client_factory()  # type: ignore[attr-defined]
    assert isinstance(client, SandboxHttpClient)

    binding = ValidatedTargetBinding.create(
        hostname="target.example",
        addresses=(ipaddress.ip_address(AUTH_IP),),
        validate=lambda _a: None,
    ).with_pinned(ipaddress.ip_address(AUTH_IP))
    from src.domain.scanning.egress import ScanNetworkContext

    request = HttpScanRequest.authorize(
        ScanNetworkContext.create(binding), HttpRequestSpec(path="/")
    )
    # execute_scan already destroyed its sandbox (finally) -> fail closed.
    with pytest.raises(SandboxNotEstablishedError):
        client.execute(request, limits=HttpLimits(), cancellation=ScanCancellation.create())


def test_engine_failure_still_destroys_sandbox() -> None:
    class ExplodingEngine(RecordingEngine):
        def execute(self, context, services) -> None:  # type: ignore[no-untyped-def]
            super().execute(context, services)
            raise RuntimeError("engine exploded")

    executor, made = _executor()
    with pytest.raises(RuntimeError, match="engine exploded"):
        executor.execute_scan("target.example", engine=ExplodingEngine())  # type: ignore[arg-type]
    (sandbox,) = made
    assert "destroy" in sandbox.events


def test_protocol_shape_matches_future_engines() -> None:
    assert isinstance(RecordingEngine(), SandboxAwareEngine)


def test_ip_addresses_in_binding_are_the_policy_source_of_truth() -> None:
    other = ipaddress.ip_address("8.8.8.8")
    binding = ValidatedTargetBinding.create(
        hostname="x.example",
        addresses=(ipaddress.ip_address(AUTH_IP),),
        validate=lambda _a: None,
    )
    policy = SandboxEgressPolicy.for_binding(binding)
    assert policy.authorize(other) is False

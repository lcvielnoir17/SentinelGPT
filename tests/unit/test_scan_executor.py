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


def _executor(*, fail_establish: bool = False):
    resolver = FakeResolver({"target.example": FakeResolver.records(AUTH_IP)})
    made: list[ScriptedSandbox] = []

    def factory(policy: SandboxEgressPolicy) -> ScriptedSandbox:
        sandbox = ScriptedSandbox(policy, fail_establish=fail_establish)
        made.append(sandbox)
        return sandbox

    executor = SandboxedScanExecutor(ScanTargetResolutionService(resolver), factory)  # type: ignore[arg-type]
    return executor, made


def test_execution_still_blocked_even_with_verified_sandbox() -> None:
    """The phase invariant: no engines exist; the final gate stays shut."""
    executor, _ = _executor()
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

    def execute(self, context, runner) -> None:  # type: ignore[no-untyped-def]
        self.calls.append((context, runner))


def test_engine_runs_inside_established_sandbox_and_cleanup_happens() -> None:
    engine = RecordingEngine()
    executor, made = _executor()
    # Bypass ONLY the no-engine invariant to observe the contract a real
    # engine will receive; every security step still runs.
    executor.execute_scan("target.example", engine=engine)  # type: ignore[arg-type]

    (sandbox,) = made
    assert sandbox.events[-1] == "destroy"
    assert sandbox.events.count("establish") == 1
    (context, runner) = engine.calls[0]
    assert [str(a) for a in context.binding.addresses] == [AUTH_IP]  # type: ignore[attr-defined]
    # The runner handed to the engine is the sandbox's own exec path.
    result = runner(["echo", "hi"])  # type: ignore[operator]
    assert result.exit_code == 0


def test_engine_failure_still_destroys_sandbox() -> None:
    class ExplodingEngine(RecordingEngine):
        def execute(self, context, runner) -> None:  # type: ignore[no-untyped-def]
            super().execute(context, runner)
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

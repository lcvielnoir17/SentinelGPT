"""Gated scan execution chain (ADR-0002/0003).

The ONLY sanctioned path from a target name toward any future scanner:

    normalize (registration-time, existing)
      -> fresh DNS resolution        [ScanTargetResolutionService]
      -> validate EVERY A/AAAA       [ip_policy via domain]
      -> ValidatedTargetBinding
      -> SandboxEgressPolicy         [binding-derived; not caller-supplied]
      -> sandbox establishment       [kernel-level egress; fail-closed]
      -> verification                [rule dump must equal the policy]
      -> require_scan_context        [Phase B gate]
      -> ENGINE GATE                 [still SCANNER_EXECUTION_BLOCKED]

No step can be skipped or reordered: the sandbox is created through an
injected factory that accepts the validated binding's policy object and
nothing else, and every exit path destroys the sandbox. Because no engine
implementation exists yet, execution still ends in
``ScannerExecutionBlockedError`` even when the whole chain succeeds —
real engines arrive only after this gate is deliberately opened.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from src.domain.errors import ScannerExecutionBlockedError
from src.domain.scanning.egress import ScanNetworkContext
from src.scanning.engines.base import require_scan_context
from src.scanning.sandbox.base import (
    EgressSandbox,
    ExecResult,
    SandboxFactory,
    require_established,
)
from src.scanning.sandbox.policy import SandboxEgressPolicy

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from uuid import UUID

    from src.domain.scanning.binding import ValidatedTargetBinding
    from src.domain.scanning.resolution import ScanTargetResolutionService


@runtime_checkable
class SandboxAwareEngine(Protocol):
    """Contract for FUTURE engines: context plus the sandbox exec path."""

    name: str

    def execute(
        self, context: ScanNetworkContext, runner: Callable[[Sequence[str]], ExecResult]
    ) -> None:  # pragma: no cover - interface only until a real engine lands
        ...


class SandboxedScanExecutor:
    """Runs the full security chain; refuses to reach any engine otherwise."""

    def __init__(
        self,
        resolution: ScanTargetResolutionService,
        sandbox_factory: SandboxFactory,
    ) -> None:
        self._resolution = resolution
        self._sandbox_factory = sandbox_factory

    def prepare(
        self,
        hostname: str,
        *,
        target_id: UUID | None = None,
        now: datetime | None = None,
    ) -> tuple[ValidatedTargetBinding, EgressSandbox]:
        """Resolve, validate, bind, and stand up the verified sandbox."""
        binding = self._resolution.resolve(hostname, target_id=target_id, now=now)
        # The allow-list exists ONLY as a projection of the binding; callers
        # of the executor cannot inject destinations at any point.
        policy = SandboxEgressPolicy.for_binding(binding)
        sandbox = self._sandbox_factory(policy)
        sandbox.establish()
        require_established(sandbox)
        return binding, sandbox

    def execute_scan(
        self,
        hostname: str,
        *,
        engine: SandboxAwareEngine | None = None,
        target_id: UUID | None = None,
        now: datetime | None = None,
    ) -> None:
        """Execute the chain end-to-end for one scan attempt."""
        binding, sandbox = self.prepare(hostname, target_id=target_id, now=now)
        try:
            context = ScanNetworkContext.create(binding)
            require_scan_context(context)
            if engine is None:
                # Phase invariant: NO engine implementation exists yet. Even
                # a fully verified sandbox does not open the execution gate;
                # that opening is a deliberate, reviewed act (ADR-0003).
                raise ScannerExecutionBlockedError()
            engine.execute(context, runner=sandbox.run)
        finally:
            sandbox.destroy()

    @staticmethod
    def _context_for(binding: ValidatedTargetBinding) -> ScanNetworkContext:
        return ScanNetworkContext.create(binding)

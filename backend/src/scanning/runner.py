"""Gated scan execution chain (ADR-0002/0003).

The ONLY sanctioned path from a target name toward a scanner engine:

    normalize (registration-time, existing)
      -> fresh DNS resolution        [ScanTargetResolutionService]
      -> validate EVERY A/AAAA       [ip_policy via domain]
      -> ValidatedTargetBinding
      -> SandboxEgressPolicy         [binding-derived; not caller-supplied]
      -> sandbox establishment       [kernel-level egress; fail-closed]
      -> verification                [rule dump must equal the policy]
      -> require_scan_context        [Phase B gate]
      -> ENGINE GATE                 [SandboxedScanExecutor.enable_execution]

No step can be skipped or reordered: the sandbox is created through an
injected factory that accepts the validated binding's policy object and
nothing else, and every exit path destroys the sandbox. Execution reaches
a real engine (``scanning/engines/http_analysis.py``) only when the
executor is composed with ``enable_execution=True`` — which happens in
exactly one place, the production composition root
(``domain/scans/pipeline.py``, ADR-0009). Every other construction keeps
the gate closed and ends in ``ScannerExecutionBlockedError``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from src.domain.errors import EgressDeniedError, ScannerExecutionBlockedError
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.http_contract import HttpLimits, ScanCancellation
from src.scanning.engines.base import require_scan_context
from src.scanning.engines.services import EngineServices, OriginSpec
from src.scanning.sandbox.base import (
    EgressSandbox,
    SandboxFactory,
    require_established,
)
from src.scanning.sandbox.http_transport import SandboxHttpClient
from src.scanning.sandbox.policy import SandboxEgressPolicy

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from src.domain.scanning.binding import ValidatedTargetBinding
    from src.domain.scanning.resolution import ScanTargetResolutionService


@runtime_checkable
class SandboxAwareEngine(Protocol):
    """Contract for FUTURE engines: validated context + scoped services.

    Engines receive NO raw networking: only the context and an
    :class:`EngineServices` bundle whose HTTP factory is bound to that same
    context (ADR-0005). Anything beyond must be a reviewed contract change.
    """

    name: str

    def execute(
        self, context: ScanNetworkContext, services: EngineServices
    ) -> object: ...  # engines return their structured result  # pragma: no cover - interface only until a real engine lands


class SandboxedScanExecutor:
    """Runs the full security chain; refuses to reach any engine otherwise.

    ``enable_execution`` is the PRODUCTION execution gate (ADR-0007): it
    defaults to False, so even a fully implemented engine is refused until
    an operator/review deliberately flips it at composition time. Tests
    that must exercise a real engine end-to-end construct the executor with
    ``enable_execution=True`` — the secure chain itself is identical in
    both modes.
    """

    def __init__(
        self,
        resolution: ScanTargetResolutionService,
        sandbox_factory: SandboxFactory,
        *,
        enable_execution: bool = False,
    ) -> None:
        self._resolution = resolution
        self._sandbox_factory = sandbox_factory
        self._enable_execution = enable_execution

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
        limits: HttpLimits | None = None,
        origin: OriginSpec | None = None,
    ) -> object:
        """Execute the chain end-to-end for one scan attempt."""
        binding, sandbox = self.prepare(hostname, target_id=target_id, now=now)
        try:
            # Pin the validated primary address before handing the context to
            # the engine: ``ConnectionTarget.for_context`` refuses an unpinned
            # binding, and the redirect-only pin path in the transport is
            # never reached for the first logical request.
            if not binding.addresses:
                raise EgressDeniedError()
            pinned_binding = binding.with_pinned(binding.addresses[0])
            context = ScanNetworkContext.create(pinned_binding)
            require_scan_context(context)
            if engine is None or not self._enable_execution:
                # Execution gate (ADR-0007): closed by default even now that
                # a real engine exists. Opening it is an explicit, reviewed
                # act at composition time (enable_execution=True), never a
                # library-level default.
                raise ScannerExecutionBlockedError()
            services = self.build_services(context, sandbox, limits, origin)
            return engine.execute(context, services)
        finally:
            sandbox.destroy()

    def build_services(
        self,
        context: ScanNetworkContext,
        sandbox: EgressSandbox,
        limits: HttpLimits | None = None,
        origin: OriginSpec | None = None,
    ) -> EngineServices:
        """Bind per-attempt capabilities to THIS context and sandbox.

        The HTTP client factory closes over the established sandbox and the
        resolution service, so every request an engine issues travels the
        same validated path; engines cannot construct a wider transport.
        """
        effective_limits = limits or HttpLimits()
        effective_origin = origin or OriginSpec()
        resolution = self._resolution

        def factory() -> SandboxHttpClient:
            return SandboxHttpClient(sandbox, resolution)

        return EngineServices(
            http_client_factory=factory,
            cancellation=ScanCancellation.create(),
            limits=effective_limits,
            origin=effective_origin,
            _context=context,
        )

    @staticmethod
    def _context_for(binding: ValidatedTargetBinding) -> ScanNetworkContext:
        return ScanNetworkContext.create(binding)

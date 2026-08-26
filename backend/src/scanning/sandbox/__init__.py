"""Runtime egress sandbox (Phase 2; ADR-0003).

This package is the DESIGNATED infrastructure zone where process/network
enforcement capability lives. Everything outside it — the domain layer and
the engine abstractions — remains network- and process-inert, enforced by
the static boundary guard.

Security model:

    validated binding -> SandboxEgressPolicy -> EgressSandbox -> scanner

The allow-list is derived exclusively from a
:class:`src.domain.scanning.binding.ValidatedTargetBinding`; callers cannot
supply an arbitrary destination list independent of the binding.
Enforcement is applied at a real runtime boundary (network namespace /
netfilter rules inside an isolated container), not as application-level
checks in front of requests.
"""

from src.scanning.sandbox.base import (
    EgressSandbox,
    ExecResult,
    SandboxFactory,
    SandboxVerification,
    require_established,
)
from src.scanning.sandbox.policy import SandboxEgressPolicy

__all__ = [
    "EgressSandbox",
    "ExecResult",
    "SandboxEgressPolicy",
    "SandboxFactory",
    "SandboxVerification",
    "require_established",
]

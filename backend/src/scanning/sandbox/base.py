"""Sandbox runtime contracts (ADR-0003).

An :class:`EgressSandbox` is a real isolation boundary with a strict
lifecycle:

    create -> install binding-derived allow-list -> verify -> run scanner
    workload -> destroy

Implementations MUST fail closed: if establishment or verification cannot
complete, execution inside the sandbox is refused rather than degraded.
The protocol intentionally exposes NO method to widen the allow-list after
establishment; the policy is installed exactly once, from the validated
binding.

This module defines contracts only — no network or process primitives of
its own. Concrete implementations live beside it in this package and carry
the documented capability exceptions in the static boundary guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from src.domain.errors import SandboxNotEstablishedError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from src.domain.scanning.ip_policy import IPAddress


@dataclass(frozen=True)
class ExecResult:
    """Outcome of one command executed inside the sandbox."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class SandboxVerification:
    """Receipt proving what egress rules are actually installed."""

    rule_dump: tuple[str, ...]
    default_drop: bool
    allowed_addresses: frozenset[IPAddress]


@runtime_checkable
class EgressSandbox(Protocol):
    """Lifecycle contract for an isolated, deny-by-default scan sandbox."""

    @property
    def established(self) -> bool:
        """True only after establish() AND successful verification."""
        ...

    def establish(self) -> SandboxVerification:
        """Create the sandbox and install the binding-derived policy.

        Raises ``SandboxUnavailableError`` when prerequisites are missing,
        ``SandboxSetupFailedError`` on any creation/installation failure.
        Never leaves a half-installed sandbox marked established.
        """
        ...

    def verify(self) -> SandboxVerification:
        """Re-read the live enforcement state; raise if it drifted."""
        ...

    def run(self, argv: Sequence[str]) -> ExecResult:
        """Execute one command INSIDE the sandbox (the only exec path)."""
        ...

    def destroy(self) -> None:
        """Tear down every sandbox resource; idempotent."""
        ...


def require_established(sandbox: EgressSandbox) -> None:
    """Gate: refuse any workload before the sandbox is proven up."""
    if not sandbox.established:
        raise SandboxNotEstablishedError()

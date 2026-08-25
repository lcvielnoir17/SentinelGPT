"""Scanner engine protocol and the execution gate (ADR-0002).

Security invariants enforced here:

1. No engine may run without a scan-time validated binding + egress
   authorization (:func:`require_scan_context` fails closed).
2. No engine implementation exists in this phase; every execution attempt is
   refused with ``SCANNER_EXECUTION_BLOCKED`` BEFORE any network activity.
   The stronger invariant holds by construction: the current phase cannot
   produce an outbound scan request at all.

This module intentionally imports no networking, process-spawning, or DNS
library of any kind. A static guard test
(tests/unit/test_scanner_boundary_static.py) locks that property in for the
whole scanner boundary package.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from src.domain.errors import ScannerExecutionBlockedError

if TYPE_CHECKING:
    from src.domain.scanning.egress import ScanNetworkContext


class ScannerEngine(Protocol):
    """Interface a real engine will implement in Phase 2 (not before)."""

    name: str

    def execute(self, context: ScanNetworkContext) -> None:  # pragma: no cover
        """Execute against an already-validated scan network context."""
        ...


def require_scan_context(context: ScanNetworkContext | None) -> ScanNetworkContext:
    """Fail closed when no validated binding/egress authorization exists."""
    if context is None:
        raise ScannerExecutionBlockedError()
    return context


class BlockedScannerEngine:
    """Placeholder engine: refuses execution unconditionally.

    Exists so wiring/UI layers can reference *an* engine without any code
    path reaching network activity. Its ``execute`` performs zero work other
    than raising the controlled domain error.
    """

    name: str = "blocked"

    def execute(self, _context: ScanNetworkContext | None) -> Any:
        raise ScannerExecutionBlockedError()

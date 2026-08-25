"""Engine execution gate: nothing may run, and nothing may run un-validated."""

import pytest

from src.domain.errors import EgressDeniedError, ScannerExecutionBlockedError
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.scanning.engines.base import BlockedScannerEngine, require_scan_context

PUBLIC_IP = "93.184.216.34"


def _context() -> ScanNetworkContext:
    addresses = (__import__("ipaddress").ip_address(PUBLIC_IP),)
    binding = ValidatedTargetBinding.create(
        hostname="gate.example",
        addresses=addresses,
        validate=lambda _a: None,
    ).with_pinned(addresses[0])
    return ScanNetworkContext.create(binding)


def test_blocked_engine_refuses_execution_unconditionally() -> None:
    engine = BlockedScannerEngine()
    with pytest.raises(ScannerExecutionBlockedError) as err:
        engine.execute(_context())
    assert err.value.code == "SCANNER_EXECUTION_BLOCKED"
    assert err.value.status_code == 501


def test_blocked_engine_refuses_even_without_context() -> None:
    with pytest.raises(ScannerExecutionBlockedError):
        BlockedScannerEngine().execute(None)


def test_execution_requires_validated_context() -> None:
    with pytest.raises(ScannerExecutionBlockedError):
        require_scan_context(None)
    assert require_scan_context(_context()) is not None


def test_gate_precedes_destination_evaluation() -> None:
    """With NO validated context the gate fires before any destination logic."""
    with pytest.raises(ScannerExecutionBlockedError):
        engine_call(None)
    # A validated context passes the gate; destination authorization still
    # independently refuses anything outside the binding.
    context = _context()
    assert require_scan_context(context) is context
    with pytest.raises(EgressDeniedError):
        context.authorize_destination(__import__("ipaddress").ip_address("6.6.6.6"))


def engine_call(context: ScanNetworkContext | None) -> str:
    """Canonical future-engine call order: gate first, then destination."""
    checked = require_scan_context(context)
    return str(checked.require_destination())

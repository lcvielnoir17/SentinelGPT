"""Research domain package (M13–M15, offline evaluation only).

Isolation contract: modules here may import the standard library and
the PURE deterministic domain functions (fingerprinting, lifecycle
derivation, priority calculation, compliance catalog, remediation
validation). They must never import scanner execution, repositories,
workers, network clients, or AI providers — a static guard in the
test suite pins this boundary, keeping research fixtures isolated
from production scanning and canonical findings untouchable.
"""

__all__: list[str] = []

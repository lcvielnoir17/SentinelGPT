"""Finding lifecycle derivation (SRS Ch4 §6.2).

Lifecycle identity: fingerprint + target_id.
Comparison is against the immediately preceding completed scan of the same
target; if the current scan has an explicit parent, that parent is used.
Rules:
  first occurrence                -> NEW
  present in previous + current   -> PERSISTENT (not REGRESSED)
  previous present, current absent-> RESOLVED
  previously RESOLVED now returns -> REGRESSED
"""

from __future__ import annotations


def derive_lifecycle_status(
    *,
    fingerprint: str,  # noqa: ARG001 — kept for traceability / future rule needs
    in_current: bool,
    in_previous: bool,
    last_known_status: str | None,
) -> str | None:
    """Derive status for one fingerprint. Returns None if no row should be emitted.

    ``fingerprint`` is part of the public contract for traceability and
    future rule extensions; the current rule does not branch on it. The
    REGRESSED determination depends only on ``last_known_status`` being
    ``RESOLVED`` before the reappearance — a fingerprint that was
    ``NEW`` then absent then returns becomes ``REGRESSED`` only when
    an explicit ``RESOLVED`` row exists in its history (otherwise the
    first reappearance is ``NEW`` because it was never marked resolved).
    """
    if in_current and not in_previous:
        if last_known_status == "RESOLVED":
            return "REGRESSED"
        return "NEW"
    if in_current and in_previous:
        return "PERSISTENT"
    if not in_current and in_previous:
        return "RESOLVED"
    return None

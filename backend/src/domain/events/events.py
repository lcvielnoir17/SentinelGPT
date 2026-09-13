"""Deterministic domain events: the notification/webhook seam.

Events derive EXCLUSIVELY from persisted state transitions — never from
AI prose, never from recomputed views:

* scan lifecycle terminal transitions (COMPLETED / FAILED);
* finding lifecycle rows written during execution (NEW / RESOLVED /
  REGRESSED; PERSISTENT rows are steady-state, not events);
* remediation workflow upserts (CHANGED, with old → new status).

Every event carries a stable ``event_id`` derived from its identity
(type, scan, fingerprint, transition, moment). Recomputing the same
transition yields the same id, so Celery retries, worker restarts, API
retries, and scheduler retries cannot create duplicates: consumers
deduplicate on ``event_id``.

No event carries secrets, tokens, cookies, or raw scanner evidence —
only identifiers, codes, and bounded transition metadata. Timestamps
come from the transition moment (scan completion, history effective
time, remediation write), never from unrelated wall-clock reads.

Deliberately out of catalog: PRIORITY_CHANGED and POSTURE_CHANGED.
Priority levels and posture summaries are live-recomputed derived views
over stored evidence — they have no persisted transition of their own,
so emitting them here would violate the rule above (and would fire on
every read, not on state change). Their changes are already observable
through this catalog: a priority or posture shift always trails a
SCAN_COMPLETED, NEW_FINDING, FINDING_RESOLVED, FINDING_REGRESSED, or
REMEDIATION_CHANGED event, whose identifiers let receivers recompute
the derived views themselves. Promoting either to an event would
require persisted per-target snapshots with their own migration and
write path — deferred, not forgotten.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import uuid

EVENT_SCHEMA_VERSION = "sgpt.events.v1"

SCAN_COMPLETED = "SCAN_COMPLETED"
SCAN_FAILED = "SCAN_FAILED"
NEW_FINDING = "NEW_FINDING"
FINDING_RESOLVED = "FINDING_RESOLVED"
FINDING_REGRESSED = "FINDING_REGRESSED"
REMEDIATION_CHANGED = "REMEDIATION_CHANGED"

EVENT_TYPES: tuple[str, ...] = (
    SCAN_COMPLETED,
    SCAN_FAILED,
    NEW_FINDING,
    FINDING_RESOLVED,
    FINDING_REGRESSED,
    REMEDIATION_CHANGED,
)

_LIFECYCLE_TO_EVENT: dict[str, str] = {
    "NEW": NEW_FINDING,
    "RESOLVED": FINDING_RESOLVED,
    "REGRESSED": FINDING_REGRESSED,
}


@dataclass(frozen=True)
class DomainEvent:
    """One deterministic state-transition event."""

    event_id: str
    event_type: str
    occurred_at: datetime
    scan_id: str | None = None
    target_id: str | None = None
    fingerprint: str | None = None
    transition: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    version: str = EVENT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at.isoformat(),
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "fingerprint": self.fingerprint,
            "transition": self.transition,
            "payload": dict(self.payload),
            "version": self.version,
        }


def make_event_id(*parts: object) -> str:
    """Stable 16-hex identity for one transition (dedupe key)."""
    canonical = "|".join(["sgpt.event.v1", *[str(p) for p in parts]])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _as_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def scan_event(
    *,
    event_type: str,
    scan_id: uuid.UUID,
    target_id: uuid.UUID | None,
    status: str,
    occurred_at: datetime,
) -> DomainEvent:
    """Build a scan-lifecycle event (COMPLETED or FAILED)."""
    moment = _as_aware(occurred_at)
    return DomainEvent(
        event_id=make_event_id(event_type, str(scan_id), status, moment.isoformat()),
        event_type=event_type,
        occurred_at=moment,
        scan_id=str(scan_id),
        target_id=str(target_id) if target_id is not None else None,
        transition=status,
    )


def lifecycle_event(
    *,
    lifecycle_status: str,
    target_id: uuid.UUID,
    fingerprint: str,
    scan_id: uuid.UUID,
    occurred_at: datetime,
    severity: str | None = None,
) -> DomainEvent | None:
    """Build a finding-lifecycle event, or None for steady states.

    Only NEW / RESOLVED / REGRESSED rows are events; PERSISTENT (and any
    unknown code) returns None — steady state is not news.
    """
    event_type = _LIFECYCLE_TO_EVENT.get(lifecycle_status)
    if event_type is None:
        return None
    moment = _as_aware(occurred_at)
    payload: dict[str, Any] = {}
    if severity is not None:
        payload["severity"] = severity
    return DomainEvent(
        event_id=make_event_id(
            event_type, str(target_id), fingerprint, str(scan_id), moment.isoformat()
        ),
        event_type=event_type,
        occurred_at=moment,
        scan_id=str(scan_id),
        target_id=str(target_id),
        fingerprint=fingerprint,
        transition=lifecycle_status,
        payload=payload,
    )


def remediation_event(
    *,
    target_id: uuid.UUID,
    fingerprint: str,
    scan_id: uuid.UUID | None,
    old_status: str | None,
    new_status: str,
    occurred_at: datetime,
    updated_by_user_id: uuid.UUID | None = None,
) -> DomainEvent:
    """Build a remediation-transition event (old may be None on first set)."""
    moment = _as_aware(occurred_at)
    return DomainEvent(
        event_id=make_event_id(
            REMEDIATION_CHANGED,
            str(target_id),
            fingerprint,
            old_status or "",
            new_status,
            moment.isoformat(),
        ),
        event_type=REMEDIATION_CHANGED,
        occurred_at=moment,
        scan_id=str(scan_id) if scan_id is not None else None,
        target_id=str(target_id),
        fingerprint=fingerprint,
        transition=f"{old_status or 'NONE'}->{new_status}",
        payload=(
            {"updated_by_user_id": str(updated_by_user_id)}
            if updated_by_user_id is not None
            else {}
        ),
    )


__all__ = [
    "DomainEvent",
    "EVENT_SCHEMA_VERSION",
    "EVENT_TYPES",
    "SCAN_COMPLETED",
    "SCAN_FAILED",
    "NEW_FINDING",
    "FINDING_RESOLVED",
    "FINDING_REGRESSED",
    "REMEDIATION_CHANGED",
    "make_event_id",
    "scan_event",
    "lifecycle_event",
    "remediation_event",
]

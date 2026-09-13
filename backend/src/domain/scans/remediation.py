"""Remediation workflow validation (operator metadata, never canonical).

Pure, network-free validation for the remediation workflow state attached
to a finding fingerprint. Validating here must never mutate fingerprints,
evidence, lifecycle, severity, or authorization — those live on the
canonical finding path. Marking a finding DONE records operator intent;
only a clean rescan can move the canonical lifecycle to RESOLVED.

M8 collaboration (same guarantees): assignment records WHO owns the
work (validated as a UUID string here; existence/activity is checked
against the user table by the service), ``due_at`` is an optional
timezone-aware deadline (naive datetimes are rejected — silent
timezone reinterpretation is worse than a 400), and comment bodies are
bounded plain text. None of these touch canonical finding data.

Transition policy (documented, deliberately permissive): any of
TODO / IN_PROGRESS / DONE / DEFERRED may move to any other, including
DONE → IN_PROGRESS (reopened work) and DONE → TODO (back to backlog).
Remediation status is operator intent, not security truth — rigidity
here would block legitimate rework flows while adding no safety, since
the canonical lifecycle only moves on deterministic scan evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

TODO = "TODO"
IN_PROGRESS = "IN_PROGRESS"
DONE = "DONE"
DEFERRED = "DEFERRED"

STATUSES = (TODO, IN_PROGRESS, DONE, DEFERRED)

MAX_NOTES_CHARS = 2_000
MAX_COMMENT_CHARS = 2_000


class RemediationValidationError(ValueError):
    """A remediation payload field failed deterministic validation."""


@dataclass(frozen=True)
class RemediationInput:
    """Validated remediation workflow payload for one fingerprint identity."""

    status: str = TODO
    notes: str | None = None
    assignee_user_id: str | None = None
    due_at: datetime | None = None
    _assignee_set: bool = False
    _due_at_set: bool = False

    @classmethod
    def parse(cls, payload: dict[str, object]) -> RemediationInput:
        """Validate a raw request payload (raises RemediationValidationError)."""
        raw_status = payload.get("status", TODO)
        if not isinstance(raw_status, str):
            raise RemediationValidationError("status must be text")
        status = raw_status.strip().upper()
        if status not in STATUSES:
            raise RemediationValidationError(f"status must be one of {sorted(STATUSES)}")
        raw_notes = payload.get("notes")
        if raw_notes is not None and not isinstance(raw_notes, str):
            raise RemediationValidationError("notes must be text")
        notes = raw_notes.strip() if isinstance(raw_notes, str) else None
        if notes is not None:
            if not notes:
                notes = None
            elif len(notes) > MAX_NOTES_CHARS:
                raise RemediationValidationError("notes exceed maximum length")
        assignee_user_id: str | None = None
        assignee_set = "assigneeUserId" in payload or "assignee_user_id" in payload
        if assignee_set:
            raw_assignee = payload.get("assigneeUserId", payload.get("assignee_user_id"))
            assignee_user_id = _parse_nullable_uuid(raw_assignee, "assigneeUserId")
        due_at: datetime | None = None
        due_at_set = "dueAt" in payload or "due_at" in payload
        if due_at_set:
            due_at = _parse_nullable_due_at(payload.get("dueAt", payload.get("due_at")))
        return cls(
            status=status,
            notes=notes,
            assignee_user_id=assignee_user_id,
            due_at=due_at,
            _assignee_set=assignee_set,
            _due_at_set=due_at_set,
        )

    @property
    def assignee_changed(self) -> bool:
        """True when the payload explicitly sets (or clears) the assignee."""
        return self._assignee_set

    @property
    def due_at_changed(self) -> bool:
        """True when the payload explicitly sets (or clears) the due date."""
        return self._due_at_set


def _parse_nullable_uuid(raw: object, field: str) -> str | None:
    """UUID string or null (null clears); anything else is a 400."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise RemediationValidationError(f"{field} must be a UUID string or null")
    import uuid as _uuid

    try:
        return str(_uuid.UUID(raw.strip()))
    except (ValueError, AttributeError) as exc:
        raise RemediationValidationError(f"{field} must be a UUID string or null") from exc


def _parse_nullable_due_at(raw: object) -> datetime | None:
    """ISO-8601 timezone-aware datetime or null (null clears).

    Naive datetimes are rejected: silently assuming UTC for an
    operator-provided deadline would corrupt overdue derivation.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise RemediationValidationError("dueAt must be an ISO-8601 datetime string or null")
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError as exc:
        raise RemediationValidationError("dueAt must be an ISO-8601 datetime string") from exc
    if parsed.tzinfo is None:
        raise RemediationValidationError("dueAt must carry timezone information")
    return parsed.astimezone(UTC)


def is_overdue(*, due_at: datetime | None, status: str, now: datetime | None = None) -> bool:
    """Deterministic overdue derivation (never persisted).

    Overdue means the deadline passed while work is still open (any
    status except DONE). DONE is never overdue — the work is complete;
    only the canonical lifecycle can say whether the vulnerability
    persists.
    """
    if due_at is None or status == DONE:
        return False
    moment = now if now is not None else datetime.now(UTC)
    aware_due = due_at if due_at.tzinfo is not None else due_at.replace(tzinfo=UTC)
    aware_now = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return aware_due <= aware_now


@dataclass(frozen=True)
class CommentInput:
    """Validated append-only remediation comment body."""

    body: str

    @classmethod
    def parse(cls, payload: dict[str, object]) -> CommentInput:
        """Validate a raw comment payload (raises RemediationValidationError)."""
        raw = payload.get("body")
        if not isinstance(raw, str):
            raise RemediationValidationError("body must be text")
        body = raw.strip()
        if not body:
            raise RemediationValidationError("body must not be empty")
        if len(body) > MAX_COMMENT_CHARS:
            raise RemediationValidationError("body exceeds maximum length")
        if "\x00" in body:
            raise RemediationValidationError("body must not contain null bytes")
        return cls(body=body)

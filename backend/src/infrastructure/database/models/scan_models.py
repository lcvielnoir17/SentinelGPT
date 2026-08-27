"""Scan lifecycle entities (SRS Chapter 4, Sections 5.2/5.3/6 & 8).

The ``scan`` row records WHICH authorization attestation validated at
scan-start time (not merely "target is authorized"), its cached aggregate
status (engine-execution rows remain the source of truth), and timestamps
for the auditable state machine (Chapter 2, Section 10).

Findings persist as one row per deterministic engine finding; the AI
assessment persists as a canonical JSON document produced by the Phase 6
validator — never replacing findings.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuthorizationAttestation(Base):
    """Versioned authorization-to-scan record (Ch. 4 §8; Ch. 5 §5).

    A confirmed, unexpired (or open-ended) attestation is REQUIRED before a
    scan may be created, and is re-checked when execution starts. Revocation
    immediately invalidates future scans.
    """

    __tablename__ = "authorization_attestation"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING_REVIEW', 'CONFIRMED', 'REVOKED')",
            name="ck_attestation_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("target.id", ondelete="RESTRICT"), nullable=False
    )
    method_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attestation_method.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence_file_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user.id", ondelete="RESTRICT"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )


class Scan(Base):
    """One analysis run against a target (Ch. 4 §5.2)."""

    __tablename__ = "scan"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("target.id", ondelete="RESTRICT"), nullable=False
    )
    scan_profile_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_profile.id", ondelete="RESTRICT"), nullable=False
    )
    initiated_by_user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    authorization_attestation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("authorization_attestation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_status.id", ondelete="RESTRICT"), nullable=False
    )
    parent_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan.id", ondelete="RESTRICT"), nullable=True
    )
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )


class ScanEngineExecution(Base):
    """What ran, at which version, with what outcome (Ch. 4 §5.3, subset)."""

    __tablename__ = "scan_engine_execution"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'TIMED_OUT')",
            name="ck_execution_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan.id", ondelete="CASCADE"), nullable=False
    )
    scan_engine_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_engine.id", ondelete="RESTRICT"), nullable=False
    )
    tool_version_snapshot: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanFinding(Base):
    """One deterministic finding persisted from an engine execution.

    Phase 9 adds identity fields (fingerprint, target/scan denormalization,
    source engine code, affected asset) to support cross-scan lifecycle
    tracking. Existing rows remain valid; new columns are nullable for
    backward compatibility and are populated for all new findings.
    """

    __tablename__ = "scan_finding"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    execution_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scan_engine_execution.id", ondelete="CASCADE"),
        nullable=False,
    )
    category_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("finding_category.id", ondelete="RESTRICT"), nullable=False
    )
    severity_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey("severity_level.id", ondelete="RESTRICT"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    location: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Phase 9 identity — nullable for backward compatibility, populated for
    # all post-migration persisted findings via canonical DB category code.
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("target.id", ondelete="RESTRICT"), nullable=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan.id", ondelete="CASCADE"), nullable=True
    )
    source_engine_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    affected_asset: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )


class FindingEvidence(Base):
    """Typed, bounded, immutable evidence rows linked to a finding."""

    __tablename__ = "finding_evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scan_finding.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_type: Mapped[str] = mapped_column(String(30), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )


class FindingStatusHistory(Base):
    """Append-oriented lifecycle history keyed by fingerprint + target."""

    __tablename__ = "finding_status_history"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("target.id", ondelete="RESTRICT"), nullable=False
    )
    finding_lifecycle_status_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("finding_lifecycle_status.id", ondelete="RESTRICT"), nullable=False
    )
    observed_in_scan_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan.id", ondelete="CASCADE"), nullable=False
    )
    effective_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )


class ScanAiAssessment(Base):
    """Canonical AI-assessment document for one execution (may be unavailable)."""

    __tablename__ = "scan_ai_assessment"
    __table_args__ = (UniqueConstraint("execution_id", name="uq_scan_ai_assessment_execution"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    execution_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scan_engine_execution.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_schema_version: Mapped[str] = mapped_column(String(10), nullable=False)
    output_schema_version: Mapped[str] = mapped_column(String(10), nullable=False)
    is_available: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    unsupported_claim_count: Mapped[int] = mapped_column(nullable=False, default=0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, server_default=func.now(), nullable=False
    )

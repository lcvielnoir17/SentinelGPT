"""Phase 7: scan lifecycle, authorization attestations & results (ADR-0009).

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-27

Adds the minimal SRS-shaped persistence for the scan lifecycle:

* ``scan_profile`` lookup (quick-check / standard / full-assessment) —
  seeded, matching Chapter 4 Section 5.1.
* ``authorization_attestation`` — versioned authorization-to-scan records
  (Chapter 4 Section 8): a CONFIRMED, unexpired attestation is required
  before any scan may be created and is re-checked at execution start.
* ``scan`` — Chapter 4 Section 5.2, recording the SPECIFIC attestation that
  authorized it plus the auditable state-machine timestamps.
* ``scan_engine_execution`` — per-engine run record (subset of Section 5.3;
  exit-code / raw-output columns intentionally deferred).
* ``scan_finding`` — one row per deterministic engine finding.
* ``scan_ai_assessment`` — canonical Phase 6 assessment/unavailable document
  (JSONB) with provenance; never a replacement for findings.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCAN_PROFILES = [
    {"id": 1, "code": "quick-check"},
    {"id": 2, "code": "standard"},
    {"id": 3, "code": "full-assessment"},
]


def upgrade() -> None:
    # ---- scan_profile lookup (Ch. 4 §5.1) ---------------------------------
    op.create_table(
        "scan_profile",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=30), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_profile")),
        sa.UniqueConstraint("code", name=op.f("uq_scan_profile_code")),
    )
    op.bulk_insert(
        sa.table(
            "scan_profile",
            sa.column("id", sa.Integer),
            sa.column("code", sa.String),
        ),
        [dict(row) for row in _SCAN_PROFILES],
    )

    # ---- authorization_attestation (Ch. 4 §8) -----------------------------
    op.create_table(
        "authorization_attestation",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("method_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("evidence_file_ref", sa.String(length=500), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('PENDING_REVIEW', 'CONFIRMED', 'REVOKED')",
            name="ck_attestation_status",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["target.id"],
            name=op.f("fk_authorization_attestation_target_id_target"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["method_id"],
            ["attestation_method.id"],
            name=op.f("fk_authorization_attestation_method_id_attestation_method"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["user.id"],
            name=op.f("fk_authorization_attestation_created_by_user_id_user"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_authorization_attestation")),
    )
    op.create_index(
        op.f("ix_authorization_attestation_target_id"),
        "authorization_attestation",
        ["target_id"],
    )

    # ---- scan (Ch. 4 §5.2) ------------------------------------------------
    op.create_table(
        "scan",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("scan_profile_id", sa.Integer(), nullable=False),
        sa.Column("initiated_by_user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("authorization_attestation_id", UUID(as_uuid=True), nullable=False),
        sa.Column("status_id", sa.Integer(), nullable=False),
        sa.Column("parent_scan_id", UUID(as_uuid=True), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["target.id"],
            name=op.f("fk_scan_target_id_target"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scan_profile_id"],
            ["scan_profile.id"],
            name=op.f("fk_scan_scan_profile_id_scan_profile"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["initiated_by_user_id"],
            ["user.id"],
            name=op.f("fk_scan_initiated_by_user_id_user"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorization_attestation_id"],
            ["authorization_attestation.id"],
            name=op.f("fk_scan_authorization_attestation_id_authorization_attestation"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["status_id"],
            ["scan_status.id"],
            name=op.f("fk_scan_status_id_scan_status"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["parent_scan_id"],
            ["scan.id"],
            name=op.f("fk_scan_parent_scan_id_scan"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan")),
    )
    op.create_index(op.f("ix_scan_target_id"), "scan", ["target_id"])
    op.create_index(op.f("ix_scan_status_id"), "scan", ["status_id"])

    # ---- scan_engine_execution (Ch. 4 §5.3 subset) ------------------------
    op.create_table(
        "scan_engine_execution",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("scan_id", UUID(as_uuid=True), nullable=False),
        sa.Column("scan_engine_id", sa.Integer(), nullable=False),
        sa.Column("tool_version_snapshot", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'TIMED_OUT')",
            name="ck_execution_status",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scan.id"],
            name=op.f("fk_scan_engine_execution_scan_id_scan"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_engine_id"],
            ["scan_engine.id"],
            name=op.f("fk_scan_engine_execution_scan_engine_id_scan_engine"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_engine_execution")),
    )
    op.create_index(op.f("ix_scan_engine_execution_scan_id"), "scan_engine_execution", ["scan_id"])

    # ---- scan_finding -----------------------------------------------------
    op.create_table(
        "scan_finding",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("execution_id", UUID(as_uuid=True), nullable=False),
        sa.Column("category_id", sa.Integer(), nullable=False),
        sa.Column("severity_id", sa.SmallInteger(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("location", sa.String(length=500), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["scan_engine_execution.id"],
            name=op.f("fk_scan_finding_execution_id_scan_engine_execution"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["category_id"],
            ["finding_category.id"],
            name=op.f("fk_scan_finding_category_id_finding_category"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["severity_id"],
            ["severity_level.id"],
            name=op.f("fk_scan_finding_severity_id_severity_level"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_finding")),
    )
    op.create_index(op.f("ix_scan_finding_execution_id"), "scan_finding", ["execution_id"])

    # ---- scan_ai_assessment -----------------------------------------------
    op.create_table(
        "scan_ai_assessment",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("execution_id", UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("prompt_schema_version", sa.String(length=10), nullable=False),
        sa.Column("output_schema_version", sa.String(length=10), nullable=False),
        sa.Column("is_available", sa.Boolean(), nullable=False),
        sa.Column("failure_kind", sa.String(length=30), nullable=True),
        sa.Column("unsupported_claim_count", sa.Integer(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["scan_engine_execution.id"],
            name=op.f("fk_scan_ai_assessment_execution_id_scan_engine_execution"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_ai_assessment")),
        sa.UniqueConstraint("execution_id", name=op.f("uq_scan_ai_assessment_execution")),
    )


def downgrade() -> None:
    op.drop_table("scan_ai_assessment")
    op.drop_table("scan_finding")
    op.drop_table("scan_engine_execution")
    op.drop_index(op.f("ix_scan_status_id"), table_name="scan")
    op.drop_index(op.f("ix_scan_target_id"), table_name="scan")
    op.drop_table("scan")
    op.drop_index(
        op.f("ix_authorization_attestation_target_id"), table_name="authorization_attestation"
    )
    op.drop_table("authorization_attestation")
    op.drop_table("scan_profile")

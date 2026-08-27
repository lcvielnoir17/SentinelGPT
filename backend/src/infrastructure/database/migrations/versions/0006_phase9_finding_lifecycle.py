"""Phase 9: finding identity & lifecycle (SRS Ch4 §6.1-6.3; Ch8 §6).

Adds fingerprint + denormalized identity columns to scan_finding for
backward-compatible cross-scan lifecycle tracking, plus typed
finding_evidence and append-oriented finding_status_history.

Existing rows are preserved; new columns are nullable and backfilled
where possible. Fingerprint generation uses the canonical persisted
finding-category code (after scan_service._map_category), not the raw
engine category.

Revision ID: 0006
Revises: 0005
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EVIDENCE_TYPES = ("RAW_HEADER", "TOOL_OUTPUT_SNIPPET", "RESPONSE_BODY_SNIPPET", "REQUEST_METADATA")


def upgrade() -> None:
    # --- scan_finding identity columns (nullable for backward compat) ---
    op.add_column("scan_finding", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.add_column("scan_finding", sa.Column("target_id", UUID(as_uuid=True), nullable=True))
    op.add_column("scan_finding", sa.Column("scan_id", UUID(as_uuid=True), nullable=True))
    op.add_column(
        "scan_finding", sa.Column("source_engine_code", sa.String(length=50), nullable=True)
    )
    op.add_column("scan_finding", sa.Column("affected_asset", sa.String(length=500), nullable=True))

    op.create_foreign_key(
        op.f("fk_scan_finding_target_id_target"),
        "scan_finding",
        "target",
        ["target_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        op.f("fk_scan_finding_scan_id_scan"),
        "scan_finding",
        "scan",
        ["scan_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_scan_finding_fingerprint", "scan_finding", ["fingerprint"])
    op.create_index(
        "ix_scan_finding_target_fingerprint", "scan_finding", ["target_id", "fingerprint"]
    )
    op.create_index("ix_scan_finding_scan_id", "scan_finding", ["scan_id"])

    # Backfill denormalized scan_id/target_id from execution -> scan join where possible.
    op.execute("""
        UPDATE scan_finding sf
        SET scan_id = se.scan_id,
            target_id = s.target_id,
            source_engine_code = se.scan_engine_id::text
        FROM scan_engine_execution se
        JOIN scan s ON s.id = se.scan_id
        WHERE sf.execution_id = se.id
          AND sf.scan_id IS NULL;
    """)
    # Source engine code backfill uses scan_engine code lookup where available.
    op.execute("""
        UPDATE scan_finding sf
        SET source_engine_code = se_code.code
        FROM scan_engine_execution se
        JOIN scan_engine se_code ON se_code.id = se.scan_engine_id
        WHERE sf.execution_id = se.id
          AND sf.source_engine_code IS NOT NULL;
    """)

    # --- finding_evidence ---
    op.create_table(
        "finding_evidence",
        sa.Column(
            "id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("finding_id", UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_type", sa.String(length=30), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"evidence_type IN {EVIDENCE_TYPES}",
            name="ck_finding_evidence_type",
        ),
        sa.CheckConstraint(
            "char_length(content) <= 2048", name="ck_finding_evidence_content_bounded"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["scan_finding.id"],
            name=op.f("fk_finding_evidence_finding_id_scan_finding"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_evidence")),
    )
    op.create_index("ix_finding_evidence_finding_id", "finding_evidence", ["finding_id"])

    # Append-only enforcement for evidence (immutable after creation)
    op.execute("""
        CREATE FUNCTION finding_evidence_is_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'finding_evidence is immutable';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER finding_evidence_no_update
        BEFORE UPDATE ON finding_evidence
        FOR EACH ROW EXECUTE FUNCTION finding_evidence_is_immutable();
    """)
    op.execute("""
        CREATE TRIGGER finding_evidence_no_delete
        BEFORE DELETE ON finding_evidence
        FOR EACH ROW EXECUTE FUNCTION finding_evidence_is_immutable();
    """)

    # --- finding_status_history ---
    op.create_table(
        "finding_status_history",
        sa.Column(
            "id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("finding_lifecycle_status_id", sa.Integer(), nullable=False),
        sa.Column("observed_in_scan_id", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "effective_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["target.id"],
            name=op.f("fk_finding_status_history_target_id_target"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_lifecycle_status_id"],
            ["finding_lifecycle_status.id"],
            name=op.f(
                "fk_finding_status_history_finding_lifecycle_status_id_finding_lifecycle_status"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["observed_in_scan_id"],
            ["scan.id"],
            name=op.f("fk_finding_status_history_observed_in_scan_id_scan"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_status_history")),
    )
    op.create_index(
        "ix_finding_status_history_fingerprint_target",
        "finding_status_history",
        ["fingerprint", "target_id"],
    )
    op.create_index(
        "ix_finding_status_history_observed_scan", "finding_status_history", ["observed_in_scan_id"]
    )
    op.create_index(
        "ix_finding_status_history_effective", "finding_status_history", ["effective_at"]
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS finding_evidence_no_delete ON finding_evidence")
    op.execute("DROP TRIGGER IF EXISTS finding_evidence_no_update ON finding_evidence")
    op.execute("DROP FUNCTION IF EXISTS finding_evidence_is_immutable()")
    op.drop_table("finding_status_history")
    op.drop_table("finding_evidence")
    op.drop_index("ix_scan_finding_scan_id", table_name="scan_finding")
    op.drop_index("ix_scan_finding_target_fingerprint", table_name="scan_finding")
    op.drop_index("ix_scan_finding_fingerprint", table_name="scan_finding")
    op.drop_constraint(op.f("fk_scan_finding_scan_id_scan"), "scan_finding", type_="foreignkey")
    op.drop_constraint(op.f("fk_scan_finding_target_id_target"), "scan_finding", type_="foreignkey")
    op.drop_column("scan_finding", "affected_asset")
    op.drop_column("scan_finding", "source_engine_code")
    op.drop_column("scan_finding", "scan_id")
    op.drop_column("scan_finding", "target_id")
    op.drop_column("scan_finding", "fingerprint")

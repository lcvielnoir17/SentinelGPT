"""Scan schedules for recurring authorized scans.

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-10

Purely additive: one new table plus an index on (enabled, next_run_at)
for the due-tick query. No existing table is touched. Downgrade drops
the table; schedules are operator configuration (re-creatable), and no
scan, finding, or lifecycle truth lives in them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_schedule",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_profile_id", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=40), nullable=True),
        sa.Column("last_detail", sa.String(length=500), nullable=True),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["scan.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scan_profile_id"], ["scan_profile.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "interval_seconds >= 600 AND interval_seconds <= 2592000",
            name="ck_schedule_interval",
        ),
    )
    op.create_index(op.f("ix_scan_schedule_owner_id"), "scan_schedule", ["owner_user_id"])
    op.create_index(op.f("ix_scan_schedule_target_id"), "scan_schedule", ["target_id"])
    op.create_index(
        "ix_scan_schedule_due",
        "scan_schedule",
        ["enabled", "next_run_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_schedule_due", table_name="scan_schedule")
    op.drop_index(op.f("ix_scan_schedule_target_id"), table_name="scan_schedule")
    op.drop_index(op.f("ix_scan_schedule_owner_id"), table_name="scan_schedule")
    op.drop_table("scan_schedule")

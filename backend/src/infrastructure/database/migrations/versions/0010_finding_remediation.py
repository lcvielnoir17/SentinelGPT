"""Finding remediation workflow state (operator metadata, never canonical).

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-08

Purely additive: one new table keyed by (fingerprint, target) with a
deduplication unique constraint and a status check constraint. No
existing table is touched, so the migration is safe to apply online and
trivial to roll back (downgrade drops the table; no canonical finding,
evidence, or lifecycle data lives in it).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_remediation",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("updated_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
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
        sa.ForeignKeyConstraint(["target_id"], ["target.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "fingerprint",
            "target_id",
            name="uq_finding_remediation_identity",
        ),
        sa.CheckConstraint(
            "status IN ('TODO', 'IN_PROGRESS', 'DONE', 'DEFERRED')",
            name="ck_remediation_status",
        ),
    )
    op.create_index(
        op.f("ix_finding_remediation_fingerprint"), "finding_remediation", ["fingerprint"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_remediation_fingerprint"), table_name="finding_remediation")
    op.drop_table("finding_remediation")

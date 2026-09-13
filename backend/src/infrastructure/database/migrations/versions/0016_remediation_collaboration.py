"""Remediation collaboration: assignment, due dates, comments (M8).

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-12

Purely additive:

* four nullable columns on ``finding_remediation`` (assignee + who/when
  assigned + optional deadline). Overdue is derived, never stored.
* one new ``remediation_comment`` table: append-only collaboration
  notes keyed by the existing (fingerprint, target) identity with a
  body-length CHECK. Comments never touch canonical finding data and
  are excluded from reports by design.

Downgrade drops the table, its index, and the columns; collaboration
metadata is operator workflow state (re-creatable), and no scan,
finding, or lifecycle truth lives in it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "finding_remediation",
        sa.Column("assignee_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "finding_remediation",
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "finding_remediation",
        sa.Column("assigned_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "finding_remediation",
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_remediation_assignee_user_id_user",
        "finding_remediation",
        "user",
        ["assignee_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_remediation_assigned_by_user_id_user",
        "finding_remediation",
        "user",
        ["assigned_by_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_table(
        "remediation_comment",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["author_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "char_length(body) >= 1 AND char_length(body) <= 2000",
            name="ck_remediation_comment_body",
        ),
    )
    op.create_index(
        "ix_remediation_comment_target_fp_created",
        "remediation_comment",
        ["target_id", "fingerprint", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_remediation_comment_target_fp_created", table_name="remediation_comment")
    op.drop_table("remediation_comment")
    op.drop_constraint(
        "fk_remediation_assigned_by_user_id_user",
        "finding_remediation",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_remediation_assignee_user_id_user",
        "finding_remediation",
        type_="foreignkey",
    )
    op.drop_column("finding_remediation", "due_at")
    op.drop_column("finding_remediation", "assigned_by_user_id")
    op.drop_column("finding_remediation", "assigned_at")
    op.drop_column("finding_remediation", "assignee_user_id")

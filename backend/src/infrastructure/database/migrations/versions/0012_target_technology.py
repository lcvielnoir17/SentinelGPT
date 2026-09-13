"""Target technology inventory (passive detection observations).

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-09

Purely additive: one new table keyed by (target_id, slug) with family /
confidence check constraints. No existing table is touched, so the
migration is safe to apply online and trivial to roll back (downgrade
drops the table; technology rows are re-derivable inventory, and no
finding, lifecycle, or priority truth lives in them — priority is
recomputed deterministically from persisted inputs).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "target_technology",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("display", sa.String(length=100), nullable=False),
        sa.Column("family", sa.String(length=20), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=True),
        sa.Column("confidence", sa.String(length=10), nullable=False),
        sa.Column("sources", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "first_observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("observed_in_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["observed_in_scan_id"], ["scan.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "target_id",
            "slug",
            name="uq_target_technology_identity",
        ),
        sa.CheckConstraint(
            "family IN ('server', 'framework', 'language', 'cms', 'proxy')",
            name="ck_technology_family",
        ),
        sa.CheckConstraint(
            "confidence IN ('HIGH', 'MEDIUM', 'LOW')",
            name="ck_technology_confidence",
        ),
    )
    op.create_index(op.f("ix_target_technology_target_id"), "target_technology", ["target_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_target_technology_target_id"), table_name="target_technology")
    op.drop_table("target_technology")

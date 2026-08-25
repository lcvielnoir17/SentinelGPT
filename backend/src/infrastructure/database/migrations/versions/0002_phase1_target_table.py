"""Phase 1: target table (SRS Chapter 4, Section 4.4).

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-25

Creates the ``target`` table: owned by exactly one entity (organization XOR
individual user, enforced by the ``single_owner`` check constraint), with a
NULLS NOT DISTINCT unique constraint on
(owner_organization_id, owner_user_id, normalized_url) so duplicate target
registration is impossible within the same owning entity — including the
personal (user-owned) case where one owner column is NULL.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "target",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("owner_organization_id", UUID(as_uuid=True), nullable=True),
        sa.Column("owner_user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("normalized_url", sa.String(length=500), nullable=False),
        sa.Column("is_archived", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["owner_organization_id"],
            ["organization.id"],
            name=op.f("fk_target_owner_organization_id_organization"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_user_id"],
            ["user.id"],
            name=op.f("fk_target_owner_user_id_user"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target")),
        sa.UniqueConstraint(
            "owner_organization_id",
            "owner_user_id",
            "normalized_url",
            name="uq_target_owner_url",
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(
            "(owner_organization_id IS NULL) != (owner_user_id IS NULL)",
            name=op.f("ck_target_single_owner"),
        ),
    )


def downgrade() -> None:
    op.drop_table("target")

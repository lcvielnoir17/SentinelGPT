"""Remove organization multi-tenancy (user-owned resource model).

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-08

Drops the ``organization`` / ``organization_membership`` tables and the
``target.owner_organization_id`` column. Every remaining target is owned
directly by its registering user, so ``target.owner_user_id`` becomes
NOT NULL with a (owner_user_id, normalized_url) uniqueness scope.

Data safety: the upgrade REFUSES to run while organization-owned target
rows still exist (they cannot be auto-reassigned — no creator mapping
exists). The operator must re-register or delete those targets first;
the error message says so. No row is ever silently orphaned or deleted
by this migration. History (0001/0002) is preserved untouched.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _org_owned_target_count() -> int:
    bind = op.get_bind()
    row = bind.execute(
        sa.text("SELECT COUNT(*) FROM target WHERE owner_organization_id IS NOT NULL")
    ).first()
    return int(row[0]) if row is not None else 0


def upgrade() -> None:
    # Offline SQL rendering has no live connection: the guard below is an
    # online-only data check (DDL still renders fully for review).
    if not op.get_context().as_sql:
        orphaned = _org_owned_target_count()
        if orphaned:
            raise RuntimeError(
                f"Migration 0011 refused: {orphaned} target row(s) are still owned by "
                "an organization (owner_organization_id IS NOT NULL). Re-register "
                "them under a user account or delete them first; this migration "
                "never reassigns or deletes user data automatically."
            )

    # --- target: drop the organization side of the old dual-owner model ---
    op.drop_constraint("uq_target_owner_url", "target", type_="unique")
    op.drop_constraint("ck_target_single_owner", "target", type_="check")
    op.drop_constraint("fk_target_owner_organization_id_organization", "target", type_="foreignkey")
    op.drop_column("target", "owner_organization_id")

    # --- membership join table (children before parents) ---
    op.drop_index(op.f("ix_organization_membership_user_id"), table_name="organization_membership")
    op.drop_index(
        op.f("ix_organization_membership_organization_id"),
        table_name="organization_membership",
    )
    op.drop_table("organization_membership")
    op.drop_table("organization")

    # --- target: single user owner from here on ---
    op.alter_column("target", "owner_user_id", existing_type=sa.UUID(), nullable=False)
    op.create_unique_constraint(
        "uq_target_owner_url", "target", ["owner_user_id", "normalized_url"]
    )


def downgrade() -> None:
    # NOTE: one-way data loss is inherent — dropped organization rows and
    # the org side of target ownership cannot be reconstructed. Structural
    # rollback only.
    op.drop_constraint("uq_target_owner_url", "target", type_="unique")
    op.alter_column("target", "owner_user_id", existing_type=sa.UUID(), nullable=True)

    op.create_table(
        "organization",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organization")),
    )
    op.create_table(
        "organization_membership",
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_organization_membership_organization_id_organization"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_organization_membership_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organization_membership")),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_membership_org_user",
        ),
        sa.CheckConstraint(
            "role IN ('ADMIN', 'MEMBER')",
            name=op.f("ck_organization_membership_role_valid"),
        ),
    )
    op.create_index(
        op.f("ix_organization_membership_organization_id"),
        "organization_membership",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_organization_membership_user_id"),
        "organization_membership",
        ["user_id"],
        unique=False,
    )

    op.add_column(
        "target",
        sa.Column("owner_organization_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_target_owner_organization_id_organization",
        "target",
        "organization",
        ["owner_organization_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        "uq_target_owner_url",
        "target",
        ["owner_organization_id", "owner_user_id", "normalized_url"],
        postgresql_nulls_not_distinct=True,
    )
    op.create_check_constraint(
        "ck_target_single_owner",
        "target",
        "(owner_organization_id IS NULL) != (owner_user_id IS NULL)",
    )

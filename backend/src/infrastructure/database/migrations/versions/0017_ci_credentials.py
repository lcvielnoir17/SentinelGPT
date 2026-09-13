"""CI/CD credentials and idempotent trigger ledger (M10).

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-12

Purely additive: two new tables. ``ci_credential`` stores only the
secret hash (plaintext is shown once and never persisted);
``ci_scan_request`` binds idempotency keys to created scans with a
partial unique index so retries return the original scan. Downgrade
drops both tables; automation credentials are operator configuration
(re-creatable), and no scan, finding, or lifecycle truth lives in them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ci_credential",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("scope", sa.String(length=20), server_default="scan", nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=20), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("scope = 'scan'", name="ck_ci_credential_scope"),
    )
    op.create_index(op.f("ix_ci_credential_owner_id"), "ci_credential", ["owner_user_id"])
    op.create_index(op.f("ix_ci_credential_target_id"), "ci_credential", ["target_id"])
    op.create_table(
        "ci_scan_request",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("policy", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("policy_version", sa.String(length=40), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["credential_id"], ["ci_credential.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ci_scan_request_credential_id"), "ci_scan_request", ["credential_id"])
    # One live claim per (credential, key); keyless triggers never collide.
    op.execute(
        "CREATE UNIQUE INDEX uq_ci_scan_request_credential_key "
        "ON ci_scan_request (credential_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_ci_scan_request_credential_key")
    op.drop_index(op.f("ix_ci_scan_request_credential_id"), table_name="ci_scan_request")
    op.drop_table("ci_scan_request")
    op.drop_index(op.f("ix_ci_credential_target_id"), table_name="ci_credential")
    op.drop_index(op.f("ix_ci_credential_owner_id"), table_name="ci_credential")
    op.drop_table("ci_credential")

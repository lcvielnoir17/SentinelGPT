"""MFA recovery codes (M11 authentication hardening).

Revision ID: 0018
Revises: 0017
Create Date: 2026-09-12

Purely additive: one new table for hashed single-use recovery codes.
The TOTP secret itself reuses the existing ``user`` columns
(``mfa_enabled``, ``mfa_secret_encrypted``) — no user-table change.
Downgrade drops the table; codes are re-generatable operator state,
and deleting a user cascades their codes.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mfa_recovery_code",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash", name=op.f("uq_mfa_recovery_code_hash")),
    )
    op.create_index(op.f("ix_mfa_recovery_code_user_id"), "mfa_recovery_code", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_mfa_recovery_code_user_id"), table_name="mfa_recovery_code")
    op.drop_table("mfa_recovery_code")

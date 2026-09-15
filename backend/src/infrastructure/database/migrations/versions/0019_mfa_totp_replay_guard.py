"""TOTP single-use replay guard (M11 authentication hardening).

Revision ID: 0019
Revises: 0018
Create Date: 2026-09-15

Purely additive: one new table recording consumed TOTP time steps per
user. Only step counters persist — never codes — and the unique
(user, step) constraint makes a replayed code fail closed. Stale rows
are pruned opportunistically by the application, so no scheduled job
is required. Downgrade drops the table; TOTP enrollment is unaffected
(the secret lives on the user row).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mfa_totp_use",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("time_step", sa.BigInteger(), nullable=False),
        sa.Column(
            "used_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "time_step", name=op.f("uq_mfa_totp_use_user_step")),
    )
    op.create_index(op.f("ix_mfa_totp_use_user_id"), "mfa_totp_use", ["user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_mfa_totp_use_user_id"), table_name="mfa_totp_use")
    op.drop_table("mfa_totp_use")

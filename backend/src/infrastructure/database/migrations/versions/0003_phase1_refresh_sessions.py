"""Phase 1: refresh-session store (SRS Chapter 11 Section 8 / Chapter 2 §9).

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-25

Creates ``refresh_session`` — one row per issued opaque refresh credential,
holding only its SHA-256 hash. Rotation chains descendants through a shared
``family_id``; presenting a ROTATED row revokes the whole family (Chapter 5,
Section 2). ON DELETE RESTRICT on ``user_id`` follows the Chapter 4 Section 13
cascade policy (CASCADE is reserved for membership-style join records).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "refresh_session",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("family_id", UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_refresh_session_user_id_user"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_session")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_session_token_hash")),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'ROTATED', 'REVOKED')",
            name=op.f("ck_refresh_session_status_valid"),
        ),
    )
    op.create_index(
        op.f("ix_refresh_session_family_id"),
        "refresh_session",
        ["family_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_refresh_session_family_id"), table_name="refresh_session")
    op.drop_table("refresh_session")

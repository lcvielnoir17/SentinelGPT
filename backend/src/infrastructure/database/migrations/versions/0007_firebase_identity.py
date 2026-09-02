"""Firebase identity bridge (ADR-0010).

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-03

Adds ``user.firebase_uid`` — the verified Firebase UID recorded at
``POST /auth/firebase`` ID-token exchange time — and relaxes
``user.password_hash`` to nullable so federated accounts (which have no
local password) can exist. The canonical SentinelGPT identity remains the
UUID ``user.id``; ``firebase_uid`` is only a federated-login mapping.

The partial unique index (firebase_uid IS NOT NULL) lets multiple
pre-bridge rows keep NULL while guaranteeing one local account per
Firebase identity.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("firebase_uid", sa.String(length=128), nullable=True),
    )
    op.alter_column("user", "password_hash", existing_type=sa.String(255), nullable=True)
    op.create_index(
        "uq_user_firebase_uid",
        "user",
        ["firebase_uid"],
        unique=True,
        postgresql_where=sa.text("firebase_uid IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_user_firebase_uid", table_name="user")
    # Federated-only accounts have no local credential; they cannot survive
    # a rollback to password-only identity, so remove them explicitly first.
    op.execute('DELETE FROM "user" WHERE password_hash IS NULL')
    op.alter_column("user", "password_hash", existing_type=sa.String(255), nullable=False)
    op.drop_column("user", "firebase_uid")

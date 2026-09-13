"""Webhook subscriptions and delivery ledger.

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-10

Purely additive: two new tables. The delivery ledger's
(webhook_id, event_id) unique constraint is the duplicate-delivery
guard; webhook deletion cascades its deliveries. Downgrade drops both
tables; subscriptions are operator configuration (re-creatable), and no
scan, finding, or lifecycle truth lives in them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "webhook",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column(
            "events",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), server_default="10", nullable=False),
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
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "timeout_seconds >= 5 AND timeout_seconds <= 60",
            name="ck_webhook_timeout",
        ),
    )
    op.create_index(op.f("ix_webhook_owner_id"), "webhook", ["owner_user_id"])

    op.create_table(
        "webhook_delivery",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("webhook_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column(
            "event_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
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
        sa.ForeignKeyConstraint(["webhook_id"], ["webhook.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "webhook_id",
            "event_id",
            name="uq_webhook_delivery_identity",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'sent', 'failed', 'cancelled')",
            name="ck_delivery_status",
        ),
    )
    op.create_index(op.f("ix_webhook_delivery_webhook_id"), "webhook_delivery", ["webhook_id"])
    op.create_index(
        "ix_webhook_delivery_retry",
        "webhook_delivery",
        ["status", "next_retry_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_webhook_delivery_retry", table_name="webhook_delivery")
    op.drop_index(op.f("ix_webhook_delivery_webhook_id"), table_name="webhook_delivery")
    op.drop_table("webhook_delivery")
    op.drop_index(op.f("ix_webhook_owner_id"), table_name="webhook")
    op.drop_table("webhook")

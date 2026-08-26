"""Migration 0005: append-only audit log (SRS Chapter 4 §10.1; ADR-0010).

Creates ``audit_log_entry`` and enforces append-only integrity with a
BEFORE UPDATE OR DELETE trigger that raises — the table physically cannot
be mutated, satisfying Chapter 4 Section 10's "survive even a bug in
application code" requirement independent of database role configuration.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log_entry",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("actor_user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("action_code", sa.String(length=50), nullable=False),
        sa.Column("entity_type", sa.String(length=30), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["user.id"],
            name=op.f("fk_audit_log_entry_actor_user_id_user"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log_entry")),
    )
    op.create_index(
        "ix_audit_entity",
        "audit_log_entry",
        ["entity_type", "entity_id", sa.text("occurred_at DESC")],
    )

    # Append-only enforcement: reject any UPDATE or DELETE at the database
    # layer, for every role including the table owner.
    op.execute("""
        CREATE FUNCTION audit_log_entry_is_append_only() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log_entry is append-only';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER audit_log_entry_no_update
        BEFORE UPDATE ON audit_log_entry
        FOR EACH ROW EXECUTE FUNCTION audit_log_entry_is_append_only();
    """)
    op.execute("""
        CREATE TRIGGER audit_log_entry_no_delete
        BEFORE DELETE ON audit_log_entry
        FOR EACH ROW EXECUTE FUNCTION audit_log_entry_is_append_only();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_entry_no_update ON audit_log_entry")
    op.execute("DROP TRIGGER IF EXISTS audit_log_entry_no_delete ON audit_log_entry")
    op.execute("DROP FUNCTION IF EXISTS audit_log_entry_is_append_only()")
    op.drop_index("ix_audit_entity", table_name="audit_log_entry")
    op.drop_table("audit_log_entry")

"""Tenant and audit lookup indexes (release audit P2-9).

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-05

The tenant-isolation predicate (``scan.initiated_by_user_id == user``)
and the audit visibility filter (``audit_log_entry.actor_user_id``)
run on every list/audit query but had no indexes — sequential scans
that grow linearly with table size. Purely additive: two indexes,
no column or constraint changes. Safe to apply online
(``CREATE INDEX`` takes a brief write lock; use CONCURRENTLY only
with an out-of-band migration, which this project does not run).
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(op.f("ix_scan_initiated_by_user_id"), "scan", ["initiated_by_user_id"])
    op.create_index(op.f("ix_audit_log_entry_actor_user_id"), "audit_log_entry", ["actor_user_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_log_entry_actor_user_id"), table_name="audit_log_entry")
    op.drop_index(op.f("ix_scan_initiated_by_user_id"), table_name="scan")

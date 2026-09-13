"""Verify-fix linkage on remediation rows (M4).

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-10

Purely additive: one nullable column linking a remediation workflow row
to the rescan created to verify the fix. Verification STATE is always
derived live (compare original vs verification scan), never stored, so
it cannot go stale; the audit log records every verify-fix request for
history. Downgrade drops the column.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "finding_remediation",
        sa.Column("verified_in_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_remediation_verified_in_scan_id_scan",
        "finding_remediation",
        "scan",
        ["verified_in_scan_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_remediation_verified_in_scan_id_scan",
        "finding_remediation",
        type_="foreignkey",
    )
    op.drop_column("finding_remediation", "verified_in_scan_id")

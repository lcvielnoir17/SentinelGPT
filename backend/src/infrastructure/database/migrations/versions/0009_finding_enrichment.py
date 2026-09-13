"""Finding enrichment table (advisory vulnerability metadata).

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-08

Purely additive: one new table keyed by (fingerprint, target) with a
deduplication unique constraint and a CVSS range check. No existing
table is touched, so the migration is safe to apply online and trivial
to roll back (downgrade drops the table; no canonical data lives in it).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_enrichment",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column("external_ref", sa.String(length=40), nullable=False),
        sa.Column("cve_id", sa.String(length=20), nullable=True),
        sa.Column("cwe_id", sa.String(length=12), nullable=True),
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("cvss_vector", sa.String(length=100), nullable=True),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("affected_technology", sa.String(length=200), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
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
        sa.ForeignKeyConstraint(["target_id"], ["target.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "fingerprint",
            "target_id",
            "source",
            "external_ref",
            name="uq_finding_enrichment_identity",
        ),
        sa.CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="cvss_range",
        ),
    )
    op.create_index(
        op.f("ix_finding_enrichment_fingerprint"), "finding_enrichment", ["fingerprint"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_enrichment_fingerprint"), table_name="finding_enrichment")
    op.drop_table("finding_enrichment")

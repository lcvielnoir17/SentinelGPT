"""Phase 0 baseline: lookup tables and core identity tables.

Revision ID: 0001
Revises:
Create Date: 2026-08-25

Creates the Chapter 4 (Section 3) lookup/reference tables plus the core
identity tables from Section 4 (user, organization, organization_membership),
and seeds the lookup data defined there. This is the v1.0 baseline migration
required by the Phase 0 deliverable (Chapter 15, Section 2).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _lookup_table(name: str, *columns: sa.Column) -> sa.Table:  # type: ignore[type-arg]
    """Helper mirroring the model definitions for bulk seed inserts."""
    return sa.Table(
        name,
        sa.MetaData(),
        *columns,
    )


severity_level_table = _lookup_table(
    "severity_level",
    sa.Column("id", sa.SmallInteger, primary_key=True),
    sa.Column("code", sa.String(20), nullable=False),
    sa.Column("label", sa.String(50), nullable=False),
    sa.Column("rank", sa.SmallInteger(), nullable=False),
)
finding_category_table = _lookup_table(
    "finding_category",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.String(50), nullable=False),
    sa.Column("label", sa.String(100), nullable=False),
    sa.Column("description", sa.Text(), nullable=True),
)
scan_status_table = _lookup_table(
    "scan_status",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.String(30), nullable=False),
)
finding_lifecycle_status_table = _lookup_table(
    "finding_lifecycle_status",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.String(20), nullable=False),
)
scan_engine_table = _lookup_table(
    "scan_engine",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.String(50), nullable=False),
    sa.Column("display_name", sa.String(100), nullable=False),
    sa.Column("category", sa.String(30), nullable=False),
    sa.Column("current_version", sa.String(50), nullable=True),
    sa.Column("is_active", sa.Boolean(), nullable=False),
)
report_format_table = _lookup_table(
    "report_format",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.String(20), nullable=False),
)
attestation_method_table = _lookup_table(
    "attestation_method",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.String(30), nullable=False),
    sa.Column("requires_manual_review", sa.Boolean(), nullable=False),
)


SEVERITY_LEVELS = [
    {"id": 0, "code": "INFO", "label": "Info", "rank": 0},
    {"id": 1, "code": "LOW", "label": "Low", "rank": 1},
    {"id": 2, "code": "MEDIUM", "label": "Medium", "rank": 2},
    {"id": 3, "code": "HIGH", "label": "High", "rank": 3},
    {"id": 4, "code": "CRITICAL", "label": "Critical", "rank": 4},
]

FINDING_CATEGORIES = [
    {
        "id": 1,
        "code": "MISSING_SECURITY_HEADER",
        "label": "Missing Security Header",
        "description": (
            "A recommended HTTP security header (e.g. HSTS, CSP, "
            "X-Content-Type-Options) is not present on a response."
        ),
    },
    {
        "id": 2,
        "code": "OUTDATED_TLS",
        "label": "Outdated TLS Configuration",
        "description": (
            "Deprecated TLS protocol versions or weak cipher suites are "
            "still negotiated by the target."
        ),
    },
    {
        "id": 3,
        "code": "KNOWN_CVE",
        "label": "Known Vulnerability (CVE)",
        "description": (
            "A template or signature match indicates exposure to a published "
            "CVE affecting the detected software version."
        ),
    },
    {
        "id": 4,
        "code": "EXPOSED_ADMIN_PANEL",
        "label": "Exposed Administrative Panel",
        "description": (
            "An administrative interface or sensitive panel is reachable "
            "without an obvious access-control boundary."
        ),
    },
    {
        "id": 5,
        "code": "DNS_MISCONFIGURATION",
        "label": "DNS Misconfiguration",
        "description": (
            "DNS records exhibit a configuration weakness such as missing "
            "SPF/DMARC or dangling records."
        ),
    },
    {
        "id": 6,
        "code": "WEAK_CIPHER",
        "label": "Weak Cipher Suite",
        "description": (
            "The TLS configuration offers cipher suites considered weak or "
            "deprecated by current guidance."
        ),
    },
]

SCAN_STATUSES = [
    {"id": 1, "code": "PENDING_ATTESTATION"},
    {"id": 2, "code": "QUEUED"},
    {"id": 3, "code": "RUNNING"},
    {"id": 4, "code": "PARTIALLY_COMPLETE"},
    {"id": 5, "code": "SCAN_COMPLETE"},
    {"id": 6, "code": "AI_ANALYSIS"},
    {"id": 7, "code": "REPORT_READY"},
    {"id": 8, "code": "REPORT_READY_DEGRADED"},
    {"id": 9, "code": "REJECTED"},
    {"id": 10, "code": "CANCELLED"},
]

FINDING_LIFECYCLE_STATUSES = [
    {"id": 1, "code": "NEW"},
    {"id": 2, "code": "PERSISTENT"},
    {"id": 3, "code": "RESOLVED"},
    {"id": 4, "code": "REGRESSED"},
]

SCAN_ENGINES = [
    {"id": 1, "code": "katana", "display_name": "Katana Crawler", "category": "crawler"},
    {"id": 2, "code": "nuclei", "display_name": "Nuclei", "category": "vulnerability"},
    {"id": 3, "code": "nikto", "display_name": "Nikto", "category": "webserver"},
    {
        "id": 4,
        "code": "headers-analyzer",
        "display_name": "Headers Analyzer",
        "category": "configuration",
    },
    {
        "id": 5,
        "code": "ssl-inspector",
        "display_name": "SSL Inspector",
        "category": "configuration",
    },
    {"id": 6, "code": "dns-lookup", "display_name": "DNS Lookup", "category": "dns"},
    {
        "id": 7,
        "code": "whois-lookup",
        "display_name": "WHOIS Lookup",
        "category": "registration",
    },
]
for engine in SCAN_ENGINES:
    engine["current_version"] = None
    engine["is_active"] = True

REPORT_FORMATS = [
    {"id": 1, "code": "PDF"},
    {"id": 2, "code": "JSON"},
    {"id": 3, "code": "CSV"},
]

ATTESTATION_METHODS = [
    {"id": 1, "code": "SELF_ATTESTATION", "requires_manual_review": False},
    {"id": 2, "code": "DNS_TXT_CHALLENGE", "requires_manual_review": True},
    {"id": 3, "code": "FILE_UPLOAD_VERIFICATION", "requires_manual_review": True},
]


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Lookup / reference tables (SRS Chapter 4, Section 3)
    # ------------------------------------------------------------------
    op.create_table(
        "severity_level",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("code", sa.String(length=20), nullable=False),
        sa.Column("label", sa.String(length=50), nullable=False),
        sa.Column("rank", sa.SmallInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_severity_level")),
        sa.UniqueConstraint("code", name=op.f("uq_severity_level_code")),
    )
    op.create_table(
        "finding_category",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_category")),
        sa.UniqueConstraint("code", name=op.f("uq_finding_category_code")),
    )
    op.create_table(
        "scan_status",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=30), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_status")),
        sa.UniqueConstraint("code", name=op.f("uq_scan_status_code")),
    )
    op.create_table(
        "finding_lifecycle_status",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=20), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_lifecycle_status")),
        sa.UniqueConstraint("code", name=op.f("uq_finding_lifecycle_status_code")),
    )
    op.create_table(
        "scan_engine",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("display_name", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=30), nullable=False),
        sa.Column("current_version", sa.String(length=50), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_engine")),
        sa.UniqueConstraint("code", name=op.f("uq_scan_engine_code")),
    )
    op.create_table(
        "report_format",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=20), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_format")),
        sa.UniqueConstraint("code", name=op.f("uq_report_format_code")),
    )
    op.create_table(
        "attestation_method",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=30), nullable=False),
        sa.Column(
            "requires_manual_review",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attestation_method")),
        sa.UniqueConstraint("code", name=op.f("uq_attestation_method_code")),
    )

    # ------------------------------------------------------------------
    # Core identity tables (SRS Chapter 4, Sections 4.1-4.3)
    # ------------------------------------------------------------------
    op.create_table(
        "user",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user")),
        sa.UniqueConstraint("email", name=op.f("uq_user_email")),
    )
    op.create_index(op.f("ix_user_email"), "user", ["email"], unique=True)

    op.create_table(
        "organization",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organization")),
    )

    op.create_table(
        "organization_membership",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organization.id"],
            name=op.f("fk_organization_membership_organization_id_organization"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_organization_membership_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organization_membership")),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_membership_org_user",
        ),
        sa.CheckConstraint(
            "role IN ('ADMIN', 'MEMBER')",
            name=op.f("ck_organization_membership_role_valid"),
        ),
    )
    op.create_index(
        op.f("ix_organization_membership_organization_id"),
        "organization_membership",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_organization_membership_user_id"),
        "organization_membership",
        ["user_id"],
        unique=False,
    )

    # ------------------------------------------------------------------
    # Lookup seed data (values fixed by SRS Chapter 4, Section 3)
    # ------------------------------------------------------------------
    op.bulk_insert(severity_level_table, SEVERITY_LEVELS)
    op.bulk_insert(finding_category_table, FINDING_CATEGORIES)
    op.bulk_insert(scan_status_table, SCAN_STATUSES)
    op.bulk_insert(finding_lifecycle_status_table, FINDING_LIFECYCLE_STATUSES)
    op.bulk_insert(scan_engine_table, SCAN_ENGINES)
    op.bulk_insert(report_format_table, REPORT_FORMATS)
    op.bulk_insert(attestation_method_table, ATTESTATION_METHODS)


def downgrade() -> None:
    # Identity tables first (children before parents).
    op.drop_index(op.f("ix_organization_membership_user_id"), table_name="organization_membership")
    op.drop_index(
        op.f("ix_organization_membership_organization_id"),
        table_name="organization_membership",
    )
    op.drop_table("organization_membership")
    op.drop_table("organization")
    op.drop_index(op.f("ix_user_email"), table_name="user")
    op.drop_table("user")

    # Lookup tables (no cross-dependencies between them).
    op.drop_table("attestation_method")
    op.drop_table("report_format")
    op.drop_table("scan_engine")
    op.drop_table("finding_lifecycle_status")
    op.drop_table("scan_status")
    op.drop_table("finding_category")
    op.drop_table("severity_level")

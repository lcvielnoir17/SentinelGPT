"""Lookup / reference table models (SRS Chapter 4, Section 3).

These are deliberately modeled as data tables rather than application-level
enums or DB-native ENUM types so that new values (a new severity tier, a new
finding category, a new engine) can be added via data insert without a schema
migration.
"""

from sqlalchemy import Boolean, SmallInteger, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database.models.base import Base


class SeverityLevel(Base):
    """Severity tiers (INFO..CRITICAL) with stable numeric ordering."""

    __tablename__ = "severity_level"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True)
    label: Mapped[str] = mapped_column(String(50))
    rank: Mapped[int] = mapped_column(SmallInteger)


class FindingCategory(Base):
    """Canonical finding categories; description doubles as AI grounding context."""

    __tablename__ = "finding_category"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)
    label: Mapped[str] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanStatus(Base):
    """Scan lifecycle states mirroring the Chapter 2 Section 10 state machine."""

    __tablename__ = "scan_status"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True)


class FindingLifecycleStatus(Base):
    """Cross-scan finding lifecycle states (NEW/PERSISTENT/RESOLVED/REGRESSED)."""

    __tablename__ = "finding_lifecycle_status"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True)


class ScanEngine(Base):
    """Registry of pluggable scan engines (SRS Chapter 2, Section 5)."""

    __tablename__ = "scan_engine"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)
    display_name: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(30))
    current_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")


class ReportFormat(Base):
    """Supported report export formats (PDF/JSON/CSV), extensible by insert."""

    __tablename__ = "report_format"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True)


class AttestationMethod(Base):
    """Authorization attestation methods (SELF_ATTESTATION in Phase 0/1 scope)."""

    __tablename__ = "attestation_method"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True)
    requires_manual_review: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )

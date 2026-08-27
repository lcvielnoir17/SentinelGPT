"""Persistence models package (SQLAlchemy 2.x declarative style).

Aggregates all model modules so Alembic's ``target_metadata`` sees every
table and autogenerate stays complete.
"""

from src.infrastructure.database.models.audit_models import AuditLogEntry
from src.infrastructure.database.models.base import Base
from src.infrastructure.database.models.identity_models import (
    Organization,
    OrganizationMembership,
    User,
)
from src.infrastructure.database.models.lookup_models import (
    AttestationMethod,
    FindingCategory,
    FindingLifecycleStatus,
    ReportFormat,
    ScanEngine,
    ScanProfile,
    ScanStatus,
    SeverityLevel,
)
from src.infrastructure.database.models.refresh_session_models import RefreshSession
from src.infrastructure.database.models.scan_models import (
    AuthorizationAttestation,
    FindingEvidence,
    FindingStatusHistory,
    Scan,
    ScanAiAssessment,
    ScanEngineExecution,
    ScanFinding,
)
from src.infrastructure.database.models.target_models import Target

__all__ = [
    "Base",
    "User",
    "Organization",
    "OrganizationMembership",
    "Target",
    "RefreshSession",
    "SeverityLevel",
    "FindingCategory",
    "ScanStatus",
    "FindingLifecycleStatus",
    "ScanEngine",
    "ScanProfile",
    "ReportFormat",
    "AttestationMethod",
    "AuthorizationAttestation",
    "Scan",
    "ScanEngineExecution",
    "ScanFinding",
    "FindingEvidence",
    "FindingStatusHistory",
    "ScanAiAssessment",
    "AuditLogEntry",
]

"""Persistence models package (SQLAlchemy 2.x declarative style).

Aggregates all model modules so Alembic's ``target_metadata`` sees every
table and autogenerate stays complete.
"""

from src.infrastructure.database.models.audit_models import AuditLogEntry
from src.infrastructure.database.models.base import Base
from src.infrastructure.database.models.ci_models import CiCredential, CiScanRequest
from src.infrastructure.database.models.identity_models import User
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
from src.infrastructure.database.models.mfa_models import MfaRecoveryCode, MfaTotpUse
from src.infrastructure.database.models.refresh_session_models import RefreshSession
from src.infrastructure.database.models.scan_models import (
    AuthorizationAttestation,
    FindingEnrichment,
    FindingEvidence,
    FindingRemediation,
    FindingStatusHistory,
    RemediationComment,
    Scan,
    ScanAiAssessment,
    ScanEngineExecution,
    ScanFinding,
    ScanSchedule,
)
from src.infrastructure.database.models.target_models import Target, TargetTechnology
from src.infrastructure.database.models.webhook_models import Webhook, WebhookDelivery

__all__ = [
    "Base",
    "User",
    "MfaRecoveryCode",
    "MfaTotpUse",
    "Target",
    "TargetTechnology",
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
    "FindingEnrichment",
    "FindingRemediation",
    "RemediationComment",
    "ScanAiAssessment",
    "ScanSchedule",
    "Webhook",
    "WebhookDelivery",
    "AuditLogEntry",
    "CiCredential",
    "CiScanRequest",
]

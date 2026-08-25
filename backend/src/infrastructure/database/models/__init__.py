"""Persistence models package (SQLAlchemy 2.x declarative style).

Aggregates all model modules so Alembic's ``target_metadata`` sees every
table and autogenerate stays complete.
"""

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
    ScanStatus,
    SeverityLevel,
)
from src.infrastructure.database.models.target_models import Target

__all__ = [
    "Base",
    "User",
    "Organization",
    "OrganizationMembership",
    "Target",
    "SeverityLevel",
    "FindingCategory",
    "ScanStatus",
    "FindingLifecycleStatus",
    "ScanEngine",
    "ReportFormat",
    "AttestationMethod",
]

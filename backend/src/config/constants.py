"""Application-wide constants for SentinelGPT."""

# API Constants
API_V1_STR: str = "/api/v1"

# Authentication cookies (SRS Chapter 2, Section 9 invariants). The refresh
# cookie is scoped to the auth routes; both share HttpOnly/Secure/SameSite=Strict.
ACCESS_TOKEN_COOKIE: str = "accessToken"
REFRESH_TOKEN_COOKIE: str = "refreshToken"
REFRESH_COOKIE_PATH: str = f"{API_V1_STR}/auth"

# CSRF mitigation header required by /auth/refresh and /auth/logout (Ch2 §9):
# cross-site form posts cannot set custom headers.
CSRF_REFRESH_HEADER: str = "X-Refresh-Request"

# Environment Names
ENV_LOCAL: str = "local"
ENV_TEST: str = "test"
ENV_STAGING: str = "staging"
ENV_PRODUCTION: str = "production"

# Scan Statuses
SCAN_STATUS_PENDING_ATTESTATION: str = "PENDING_ATTESTATION"
SCAN_STATUS_QUEUED: str = "QUEUED"
SCAN_STATUS_RUNNING: str = "RUNNING"
SCAN_STATUS_PARTIALLY_COMPLETE: str = "PARTIALLY_COMPLETE"
SCAN_STATUS_SCAN_COMPLETE: str = "SCAN_COMPLETE"
SCAN_STATUS_AI_ANALYSIS: str = "AI_ANALYSIS"
SCAN_STATUS_REPORT_READY: str = "REPORT_READY"
SCAN_STATUS_REPORT_READY_DEGRADED: str = "REPORT_READY_DEGRADED"
SCAN_STATUS_REJECTED: str = "REJECTED"
SCAN_STATUS_CANCELLED: str = "CANCELLED"

# Engine Codes
ENGINE_HEADERS: str = "headers-analyzer"

# Celery queue names (SRS Ch6 §6: separate queues per concern).
CELERY_QUEUE_SCAN: str = "scan"

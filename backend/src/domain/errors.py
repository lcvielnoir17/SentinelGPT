"""Domain-specific exceptions mapped to the SRS error catalog (Chapter 5,
Section 14) by the centralized FastAPI exception handlers."""

from __future__ import annotations


class DomainError(Exception):
    """Base class for business-rule violations with HTTP mapping metadata."""

    status_code: int
    code: str
    message: str

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)


class EmailAlreadyRegisteredError(DomainError):
    """Registration attempted with an email that already exists (409 CONFLICT)."""

    status_code = 409
    code = "CONFLICT"
    message = "An account with this email already exists."


class InvalidCredentialsError(DomainError):
    """Login failed — identical for unknown email and wrong password (401)."""

    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Invalid email or password."


class NotAuthenticatedError(DomainError):
    """Request lacks valid authentication credentials (401 UNAUTHENTICATED)."""

    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Authentication required."


class ForbiddenError(DomainError):
    """Authenticated requester lacks permission for the resource (403)."""

    status_code = 403
    code = "FORBIDDEN"
    message = "You do not have permission to access this resource."


class NotFoundError(DomainError):
    """Resource does not exist or is not visible to the requester (404).

    Per SRS Chapter 5, Section 14, cross-tenant resources are reported as
    NOT_FOUND (never FORBIDDEN) so the API leaks no information about other
    organizations' data.
    """

    status_code = 404
    code = "NOT_FOUND"
    message = "Resource not found."


class DuplicateTargetError(DomainError):
    """Target already registered for the owning entity (409 CONFLICT)."""

    status_code = 409
    code = "CONFLICT"
    message = "A target with this URL is already registered for this owner."


class InvalidTargetError(DomainError):
    """Hostname/URL failed normalization/validation rules (422).

    Covers SSRF-prevention rejections (private ranges, localhost, cloud
    metadata) per SRS Chapter 5, Section 4 / Chapter 2, Section 13.
    """

    status_code = 422
    code = "UNPROCESSABLE_TARGET"
    message = "Hostname/URL failed normalization/validation rules."


class InvalidPaginationCursorError(DomainError):
    """Malformed pagination cursor supplied to a list endpoint (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid pagination cursor."


class RefreshCsrfHeaderMissingError(DomainError):
    """/auth/refresh or /auth/logout called without the CSRF-mitigation
    header that only same-origin JavaScript can set (403, Chapter 2 §9)."""

    status_code = 403
    code = "FORBIDDEN"
    message = "Missing required X-Refresh-Request header."


# ---------------------------------------------------------------------------
# Scanner security boundary (SRS Chapter 11 Section 6; ADR-0001/0002).
# Client-facing messages stay generic: DNS/infrastructure detail is logged
# server-side only.
# ---------------------------------------------------------------------------


class TargetUnresolvedError(DomainError):
    """Scan-time resolution produced no usable address set (503)."""

    status_code = 503
    code = "TARGET_UNRESOLVED"
    message = "Target could not be resolved for scanning."


class TargetResolutionBlockedError(DomainError):
    """A resolved address (or redirect destination) is prohibited (403).

    Per SRS Chapter 5, Section 14: TARGET_RESOLUTION_BLOCKED.
    """

    status_code = 403
    code = "TARGET_RESOLUTION_BLOCKED"
    message = "Target resolves to a disallowed address."


class DnsRebindingDetectedError(TargetResolutionBlockedError):
    """Connection-time resolution disagrees with the validated binding.

    Shares the generic TARGET_RESOLUTION_BLOCKED envelope — rebinding
    detection detail remains server-side.
    """


class RedirectDestinationBlockedError(TargetResolutionBlockedError):
    """A redirect destination failed revalidation (same generic envelope)."""


class EgressDeniedError(DomainError):
    """Destination outside the validated binding's address set (403)."""

    status_code = 403
    code = "EGRESS_DENIED"
    message = "Destination is not authorized by the scan egress policy."


class ScannerExecutionBlockedError(DomainError):
    """Any scanner-engine execution attempt in this phase (501).

    Chapter 15 Phase 2 places real engines behind an explicit guard; until
    that phase lands, execution is structurally refused BEFORE any network
    activity can occur.
    """

    status_code = 501
    code = "SCANNER_EXECUTION_BLOCKED"
    message = "Scanner execution is not available."

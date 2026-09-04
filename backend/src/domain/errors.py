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


class InvalidAttestationError(DomainError):
    """Attestation parameters failed validation (400).

    Covers unusable expiry values (naive or already-past ``expires_at``):
    an authorization that is expired before it is created can never
    authorize a scan, so it is rejected instead of persisted as a dead row.
    """

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid attestation parameters."


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


# ---------------------------------------------------------------------------
# Runtime egress sandbox (Phase 2; ADR-0003). Infrastructure failures are
# fail-closed: an unestablishable/unverifiable sandbox must never degrade
# into "run anyway". Client messages stay generic; detail is server-side.
# ---------------------------------------------------------------------------


class SandboxUnavailableError(DomainError):
    """The runtime lacks sandbox prerequisites entirely (503)."""

    status_code = 503
    code = "SANDBOX_UNAVAILABLE"
    message = "Scan sandbox is not available on this runtime."


class SandboxSetupFailedError(DomainError):
    """Sandbox creation or egress-policy installation failed (503)."""

    status_code = 503
    code = "SANDBOX_SETUP_FAILED"
    message = "Scan sandbox could not be established."


class SandboxVerificationFailedError(DomainError):
    """Post-installation verification contradicted the requested policy (503)."""

    status_code = 503
    code = "SANDBOX_VERIFICATION_FAILED"
    message = "Scan sandbox failed verification."


class SandboxNotEstablishedError(DomainError):
    """Execution was attempted before sandbox establishment succeeded (503)."""

    status_code = 503
    code = "SANDBOX_NOT_ESTABLISHED"
    message = "Scan sandbox is not established."


class AttestationNotConfirmedError(DomainError):
    """Scan creation/execution blocked: no valid authorization attestation.

    SRS Chapter 5, Section 6 / Chapter 4, Section 8 (403
    ATTESTATION_NOT_CONFIRMED). Target registration alone never authorizes
    network execution.
    """

    status_code = 403
    code = "ATTESTATION_NOT_CONFIRMED"
    message = "Target does not have a confirmed authorization attestation."


class InvalidScanStateError(DomainError):
    """A lifecycle transition violated the scan state machine (409)."""

    status_code = 409
    code = "SCAN_INVALID_STATE"
    message = "Requested operation is not valid for the current scan state."


class FirebaseTokenInvalidError(DomainError):
    """Firebase ID token failed verification (401 UNAUTHENTICATED).

    One generic failure surface for every token problem (bad signature,
    wrong audience/issuer, expired, malformed) so the endpoint leaks no
    verification internals.
    """

    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Firebase ID token verification failed."


class FeatureDisabledError(DomainError):
    """The requested capability is not configured on this deployment (503)."""

    status_code = 503
    code = "FEATURE_DISABLED"
    message = "This feature is not enabled on this deployment."

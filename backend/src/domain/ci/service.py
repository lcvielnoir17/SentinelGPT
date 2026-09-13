"""CI service: credentials, bearer auth, trigger, result (M10).

The CI API is another authenticated entry point into the EXISTING
scan system — every trigger flows through
``ScanService.create_scan`` (ownership, attestation, rate/queue
limits) and ``enqueue_scan`` (execution gate). No scan logic is
duplicated here; this service only adds credential handling,
target binding, idempotency claims, and deterministic policy
evaluation on top.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import IntegrityError

from src.domain.audit.audit_service import (
    ACTION_CI_CREDENTIAL_CREATED,
    ACTION_CI_CREDENTIAL_REVOKED,
    ACTION_CI_CREDENTIAL_ROTATED,
    ACTION_CI_SCAN_REJECTED,
    ACTION_CI_SCAN_REQUESTED,
    AuditService,
)
from src.domain.ci import tokens
from src.domain.ci.errors import CiAuthError, CiConflictError, InvalidCiError
from src.domain.ci.policy import POLICY_VERSION, evaluate_policy, parse_policy
from src.domain.ci.validation import (
    parse_expires_at,
    parse_idempotency_key,
    parse_name,
    parse_scan_profile,
)
from src.domain.errors import DomainError, NotFoundError
from src.infrastructure.database.models import CiCredential, CiScanRequest
from src.infrastructure.database.repositories.ci_repository import CiRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

CI_SCOPE = "scan"


@dataclass(frozen=True)
class CiCredentialContext:
    """An authenticated automation call: credential row + owner account."""

    credential: CiCredential
    owner: UserAccount


@dataclass(frozen=True)
class CreatedCredential:
    """Credential metadata plus the plaintext shown exactly once."""

    id: uuid.UUID
    name: str
    target_id: uuid.UUID
    key_prefix: str
    secret: str
    expires_at: datetime | None
    created_at: datetime


class CiService:
    """Credential lifecycle (session principal) + automation plane (bearer)."""

    def __init__(self, session: AsyncSession, principal: UserAccount | None) -> None:
        self._session = session
        self._principal = principal
        self._repository = CiRepository(session)
        self._pending_claim: CiScanRequest | None = None

    def _owner(self) -> UserAccount:
        """Session owner (bearer auth resolves identity from the token)."""
        from src.domain.errors import NotAuthenticatedError

        if self._principal is None:
            raise NotAuthenticatedError()
        return self._principal

    # ------------------------------------------------------------------ #
    # Credential lifecycle (browser session, owner = principal)            #
    # ------------------------------------------------------------------ #

    async def create_credential(
        self, *, name: str, target_id: uuid.UUID, expires_at: str | None = None
    ) -> CreatedCredential:
        """Create a target-bound credential; plaintext returned exactly once."""
        from src.domain.targets.target_service import TargetService

        clean_name = parse_name(name)
        clean_expiry = parse_expires_at(expires_at)
        target = await TargetService(self._session, self._owner()).get_target(target_id)
        now = datetime.now(UTC)
        credential = CiCredential(
            id=uuid.uuid4(),
            owner_user_id=self._owner().id,
            target_id=target.id,
            name=clean_name,
            scope=CI_SCOPE,
            secret_hash="",
            key_prefix="",
            created_at=now,
            expires_at=clean_expiry,
        )
        secret = tokens.generate_secret()
        credential.secret_hash = tokens.hash_secret(secret)
        credential.key_prefix = tokens.key_prefix_for(secret)
        self._repository.add_credential(credential)
        await self._repository.flush()
        await AuditService(self._session).record(
            action_code=ACTION_CI_CREDENTIAL_CREATED,
            entity_type="ci_credential",
            entity_id=credential.id,
            metadata_json={
                "name": clean_name,
                "targetId": str(target.id),
                "keyPrefix": credential.key_prefix,
                "expiresAt": clean_expiry.isoformat() if clean_expiry else None,
            },
            actor_user_id=self._owner().id,
            occurred_at=now,
        )
        return CreatedCredential(
            id=credential.id,
            name=clean_name,
            target_id=target.id,
            key_prefix=credential.key_prefix,
            secret=tokens.build_plaintext(credential.id, secret),
            expires_at=clean_expiry,
            created_at=now,
        )

    async def list_credentials(self) -> list[dict[str, Any]]:
        """Credential metadata for the owner (never any secret material)."""
        rows = await self._repository.list_for_owner(self._owner().id)
        return [_credential_metadata(row) for row in rows]

    async def rotate_credential(self, credential_id: uuid.UUID) -> CreatedCredential:
        """Replace the secret; the old bearer dies immediately."""
        credential = await self._get_owned_credential(credential_id)
        now = datetime.now(UTC)
        secret = tokens.generate_secret()
        credential.secret_hash = tokens.hash_secret(secret)
        credential.key_prefix = tokens.key_prefix_for(secret)
        credential.revoked_at = None
        await self._repository.flush()
        await AuditService(self._session).record(
            action_code=ACTION_CI_CREDENTIAL_ROTATED,
            entity_type="ci_credential",
            entity_id=credential.id,
            metadata_json={
                "targetId": str(credential.target_id),
                "keyPrefix": credential.key_prefix,
            },
            actor_user_id=self._owner().id,
            occurred_at=now,
        )
        return CreatedCredential(
            id=credential.id,
            name=credential.name,
            target_id=credential.target_id,
            key_prefix=credential.key_prefix,
            secret=tokens.build_plaintext(credential.id, secret),
            expires_at=credential.expires_at,
            created_at=credential.created_at,
        )

    async def revoke_credential(self, credential_id: uuid.UUID) -> None:
        """Revoke (idempotent: revoking twice is still success)."""
        credential = await self._get_owned_credential(credential_id)
        if credential.revoked_at is None:
            credential.revoked_at = datetime.now(UTC)
            await self._repository.flush()
            await AuditService(self._session).record(
                action_code=ACTION_CI_CREDENTIAL_REVOKED,
                entity_type="ci_credential",
                entity_id=credential.id,
                metadata_json={"targetId": str(credential.target_id)},
                actor_user_id=self._owner().id,
            )

    async def _get_owned_credential(self, credential_id: uuid.UUID) -> CiCredential:
        credential = await self._repository.get_credential(credential_id)
        if credential is None or credential.owner_user_id != self._owner().id:
            raise NotFoundError()
        return credential

    # ------------------------------------------------------------------ #
    # Bearer plane (Automation: Authorization: Bearer <token>)            #
    # ------------------------------------------------------------------ #

    async def authenticate(self, authorization_header: str | None) -> CiCredentialContext:
        """Validate a bearer token (identical 401 for every failure mode)."""
        from src.domain.users.user_service import UserAccount
        from src.infrastructure.database.repositories.user_repository import UserRepository

        parsed = _parse_bearer(authorization_header)
        credential = None
        secret = ""
        if parsed is not None:
            credential_id, secret = parsed
            credential = await self._repository.get_credential(credential_id)
        if credential is None or not tokens.verify_secret(secret, credential.secret_hash):
            _dummy_compare()
            raise CiAuthError()
        now = datetime.now(UTC)
        if credential.revoked_at is not None:
            raise CiAuthError()
        if credential.expires_at is not None and _as_aware(credential.expires_at) <= now:
            raise CiAuthError()
        owner_row = await UserRepository(self._session).get_by_id(credential.owner_user_id)
        if owner_row is None or not owner_row.is_active:
            raise CiAuthError()
        credential.last_used_at = now
        await self._repository.flush()
        return CiCredentialContext(
            credential=credential,
            owner=UserAccount(
                id=owner_row.id, email=owner_row.email, created_at=owner_row.created_at
            ),
        )

    async def trigger_scan(
        self,
        context: CiCredentialContext,
        *,
        scan_profile: str | None = None,
        idempotency_key: str | None = None,
        policy: object = None,
    ) -> dict[str, Any]:
        """Trigger a scan on the credential's bound target (202/200).

        Same credential + key returns the original scan (200,
        ``idempotent: true``) with the FIRST request's policy —
        first-writer-wins keeps retries deterministic. A key claimed
        by an in-flight creation answers 409 (retry to observe it).
        Without a key every call creates a fresh scan.

        Rejections roll the trigger transaction back, then persist the
        rejection audit in a fresh commit so the trail survives.
        """

        profile = parse_scan_profile(scan_profile)
        key = parse_idempotency_key(idempotency_key)
        parsed_policy = parse_policy(policy)
        credential = context.credential
        owner = context.owner

        if key is not None:
            claim = await self._claim_key(credential, key)
            if claim is not None:
                return claim

        service = self._scan_service(owner)
        try:
            details = await service.create_scan(
                target_id=credential.target_id, scan_profile_code=profile
            )
        except LookupError as exc:
            await self._persist_rejection(
                credential, owner, "unknown_scan_profile", key, parsed_policy
            )
            raise InvalidCiError("Unknown scan profile.") from exc
        except DomainError as exc:
            await self._persist_rejection(credential, owner, type(exc).__name__, key, parsed_policy)
            raise

        request_row = CiScanRequest(
            credential_id=credential.id,
            idempotency_key=key,
            scan_id=details.id,
            policy=parsed_policy,
            policy_version=POLICY_VERSION if parsed_policy is not None else None,
            detail=None,
        )
        if key is not None:
            await self._attach_scan_to_claim(credential, key, request_row, details.id)
        else:
            self._repository.add_request(request_row)
            await self._repository.flush()
        await AuditService(self._session).record(
            action_code=ACTION_CI_SCAN_REQUESTED,
            entity_type="scan",
            entity_id=details.id,
            metadata_json={
                "credentialId": str(credential.id),
                "targetId": str(credential.target_id),
                "scanProfile": profile,
                "idempotent": False,
                "policy": parsed_policy,
                "policyVersion": POLICY_VERSION if parsed_policy is not None else None,
                "ownerUserId": str(owner.id),
            },
            actor_user_id=owner.id,
        )
        await self._session.commit()
        dispatched = await self._dispatch(details.id)
        return {
            "scan_id": details.id,
            "status": details.status_code,
            "target_id": details.target_id,
            "idempotent": False,
            "dispatched": dispatched,
        }

    async def _persist_rejection(
        self,
        credential: CiCredential,
        owner: UserAccount,
        reason: str,
        key: str | None,
        parsed_policy: dict[str, Any] | None,
    ) -> None:
        """Roll back the failed trigger, then persist the rejection audit.

        The rollback also releases our idempotency claim, so a later
        retry with the same key starts fresh instead of wedging on a
        scan-less row.
        """
        await self._session.rollback()
        self._pending_claim = None
        await self._audit_reject(credential, owner, reason, key, parsed_policy)
        await self._session.commit()

    async def get_result(self, context: CiCredentialContext, scan_id: uuid.UUID) -> dict[str, Any]:
        """Bounded deterministic result for one scan (credential target only)."""
        from src.domain.compliance.catalog import MAPPING_VERSION
        from src.domain.scans.priority import PRIORITY_VERSION_V2
        from src.domain.scans.scan_service import ScanService
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )
        from src.reporting.assembler import REPORT_SCHEMA_VERSION

        credential = context.credential
        owner = context.owner
        service = ScanService(self._session, owner)
        try:
            details = await service.get_scan(scan_id)
        except NotFoundError:
            raise NotFoundError() from None
        if details.target_id != credential.target_id:
            # Tighter than user scope: the credential sees only its target.
            raise NotFoundError()

        executions = ScanEngineExecutionRepository(self._session)
        finding_dtos = await executions.list_finding_dtos(scan_id)
        severity_counts: dict[str, int] = {}
        for dto in finding_dtos:
            severity = str(dto.get("severity", "") or "")
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        lifecycle_map = await PostureRepository(self._session).lifecycle_at_scan(
            details.target_id, scan_id
        )
        lifecycle_counts: dict[str, int] = {}
        for code in lifecycle_map.values():
            lifecycle_counts[code] = lifecycle_counts.get(code, 0) + 1
        remediation_counts: dict[str, int] = {}
        untracked = 0
        remediation_map = await executions.list_remediations_for_target(target_id=details.target_id)
        fingerprints = {str(d.get("fingerprint", "") or "") for d in finding_dtos}
        for fingerprint in fingerprints:
            row = remediation_map.get(fingerprint) if fingerprint else None
            if row is None:
                untracked += 1
            else:
                status = str(row.get("status", "TODO"))
                remediation_counts[status] = remediation_counts.get(status, 0) + 1
        remediation_counts["UNTRACKED"] = untracked

        stored = await self._request_for_scan(credential.id, scan_id)
        stored_policy = stored.policy if stored is not None else None
        stored_version = stored.policy_version if stored is not None else None
        outcome = evaluate_policy(
            scan_status=details.status_code,
            severity_counts=severity_counts,
            has_regression=bool(lifecycle_counts.get("REGRESSED")),
            policy=dict(stored_policy) if isinstance(stored_policy, dict) else None,
        )
        return {
            "scan_id": str(details.id),
            "target_id": str(details.target_id),
            "status": details.status_code,
            "queued_at": details.queued_at.isoformat() if details.queued_at else None,
            "started_at": details.started_at.isoformat() if details.started_at else None,
            "completed_at": details.completed_at.isoformat() if details.completed_at else None,
            "finding_count": len(finding_dtos),
            "severity_counts": dict(sorted(severity_counts.items())),
            "lifecycle_counts": dict(sorted(lifecycle_counts.items())),
            "remediation_summary": dict(sorted(remediation_counts.items())),
            "policy": {
                "state": outcome["state"],
                "reason": outcome["reason"],
                "version": stored_version,
                "configured": stored_policy is not None,
            },
            "references": {
                "reportSchemaVersion": REPORT_SCHEMA_VERSION,
                "priorityVersion": PRIORITY_VERSION_V2,
                "complianceMappingVersion": MAPPING_VERSION,
            },
        }

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    def _scan_service(self, owner: UserAccount) -> Any:
        """ScanService with the SAME limiter/caps as interactive creation."""
        from src.config.settings import get_settings
        from src.domain.scans.rate_limit import RedisAtomicRateLimiter
        from src.domain.scans.scan_service import ScanService
        from src.infrastructure.cache.redis_client import get_redis_client

        settings = get_settings()
        return ScanService(
            self._session,
            owner,
            scan_limiter=RedisAtomicRateLimiter(
                get_redis_client(),
                key_prefix="sgpt:scan:create",
                limit=settings.scan_rate_limit_per_minute,
                window_seconds=60,
            ),
            max_queued_per_user=settings.scan_max_queued_per_user,
            max_running_per_user=settings.scan_max_running_per_user,
        )

    async def _claim_key(self, credential: CiCredential, key: str) -> dict[str, Any] | None:
        """Claim (credential, key); None means 'caller creates the scan'.

        A duplicate claim resolves to the winner: completed mapping →
        the original scan (200 idempotent), scan-less row → 409 retry.
        """
        claim = CiScanRequest(credential_id=credential.id, idempotency_key=key, scan_id=None)
        try:
            async with self._session.begin_nested():
                self._session.add(claim)
                await self._session.flush()
        except IntegrityError:
            winner = await self._repository.get_request_by_key(credential.id, key)
            if winner is None or winner.scan_id is None:
                raise CiConflictError() from None
            return await self._idempotent_result(credential, winner)
        self._pending_claim = claim
        return None

    async def _attach_scan_to_claim(
        self,
        credential: CiCredential,
        key: str,
        request_row: CiScanRequest,
        scan_id: uuid.UUID,
    ) -> None:
        """Point our claimed row at the created scan (same transaction)."""
        claim = getattr(self, "_pending_claim", None)
        if claim is not None and getattr(claim, "credential_id", None) == credential.id:
            claim.scan_id = scan_id
            claim.policy = request_row.policy
            claim.policy_version = request_row.policy_version
            await self._session.flush()
            self._pending_claim = None
            return
        request_row.credential_id = credential.id
        request_row.idempotency_key = key
        self._repository.add_request(request_row)
        await self._session.flush()

    async def _idempotent_result(
        self, credential: CiCredential, winner: CiScanRequest
    ) -> dict[str, Any]:
        """Rebuild the trigger response for a duplicate idempotency key."""
        from src.domain.scans.scan_service import ScanService
        from src.infrastructure.database.repositories.user_repository import UserRepository

        assert winner.scan_id is not None
        owner_row = await UserRepository(self._session).get_by_id(credential.owner_user_id)
        if owner_row is None:
            raise NotFoundError()
        from src.domain.users.user_service import UserAccount

        owner = UserAccount(id=owner_row.id, email=owner_row.email, created_at=owner_row.created_at)
        details = await ScanService(self._session, owner).get_scan(winner.scan_id)
        await AuditService(self._session).record(
            action_code=ACTION_CI_SCAN_REQUESTED,
            entity_type="scan",
            entity_id=details.id,
            metadata_json={
                "credentialId": str(credential.id),
                "targetId": str(details.target_id),
                "idempotent": True,
                "ownerUserId": str(owner.id),
            },
            actor_user_id=owner.id,
        )
        return {
            "scan_id": details.id,
            "status": details.status_code,
            "target_id": details.target_id,
            "idempotent": True,
            "dispatched": True,
        }

    async def _request_for_scan(
        self, credential_id: uuid.UUID, scan_id: uuid.UUID
    ) -> CiScanRequest | None:
        """Latest trigger row binding this credential+scan (policy source)."""
        from sqlalchemy import select

        result = await self._session.execute(
            select(CiScanRequest)
            .where(
                CiScanRequest.credential_id == credential_id,
                CiScanRequest.scan_id == scan_id,
            )
            .order_by(CiScanRequest.created_at.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def _audit_reject(
        self,
        credential: CiCredential,
        owner: UserAccount,
        reason: str,
        key: str | None,
        parsed_policy: dict[str, Any] | None,
    ) -> None:
        await AuditService(self._session).record(
            action_code=ACTION_CI_SCAN_REJECTED,
            entity_type="ci_credential",
            entity_id=credential.id,
            metadata_json={
                "reason": reason,
                "targetId": str(credential.target_id),
                "idempotencyKey": key,
                "policy": parsed_policy,
                "ownerUserId": str(owner.id),
            },
            actor_user_id=owner.id,
        )

    async def _dispatch(self, scan_id: uuid.UUID) -> bool:
        """Enqueue after commit; broker failure stays an honest 202."""
        from src.workers.scan_tasks import enqueue_scan

        try:
            return bool(enqueue_scan(scan_id))
        except Exception:
            return False


def _credential_metadata(credential: CiCredential) -> dict[str, Any]:
    return {
        "id": credential.id,
        "name": credential.name,
        "target_id": credential.target_id,
        "scope": credential.scope,
        "key_prefix": credential.key_prefix,
        "created_at": credential.created_at,
        "last_used_at": credential.last_used_at,
        "expires_at": credential.expires_at,
        "revoked_at": credential.revoked_at,
    }


def _parse_bearer(authorization_header: str | None) -> tuple[uuid.UUID, str] | None:
    if not authorization_header:
        return None
    scheme, separator, token = authorization_header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        return None
    return tokens.parse_plaintext(token.strip())


def _dummy_compare() -> None:
    """Constant-time no-op so missing ids cost what a real check costs."""
    import hmac as _hmac

    _hmac.compare_digest("0" * 64, "1" * 64)


def _as_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


__all__ = ["CI_SCOPE", "CiCredentialContext", "CiService", "CreatedCredential"]

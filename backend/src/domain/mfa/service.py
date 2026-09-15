"""MFA service: TOTP enrollment, challenge, recovery, disable (M11).

Additive over the session architecture: enrollment stores an
ENCRYPTED pending secret that only activates after a successful
verification; login with an enabled factor mints a short-lived
challenge token (never a session); verification consumes TOTP or a
single-use recovery code and only then issues the normal session.
Secrets and codes never reach logs, audits, or post-enrollment
responses — audits carry ids and outcomes only.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.domain.audit.audit_service import (
    ACTION_MFA_CHALLENGE_FAILURE,
    ACTION_MFA_CHALLENGE_SUCCESS,
    ACTION_MFA_DISABLED,
    ACTION_MFA_ENABLED,
    ACTION_MFA_ENROLL_STARTED,
    ACTION_MFA_RECOVERY_GENERATED,
    ACTION_MFA_RECOVERY_REGENERATED,
    ACTION_MFA_RECOVERY_USED,
    ACTION_MFA_SECRET_REPLACED,
    AuditService,
)
from src.domain.errors import NotAuthenticatedError
from src.domain.mfa.errors import (
    InvalidMfaError,
    MfaConflictError,
    MfaNotConfiguredError,
    MfaRateLimitedError,
)
from src.domain.mfa.totp import generate_secret, matching_step, provisioning_uri, verify_code
from src.infrastructure.secrets.mfa_box import (
    MfaSecretsNotConfiguredError,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_recovery_codes,
    hash_recovery_code,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

RECOVERY_CODE_COUNT = 10


@dataclass(frozen=True)
class EnrollmentStarted:
    """Provisioning material, returned exactly once per enrollment."""

    provisioning_uri: str
    secret: str


@dataclass(frozen=True)
class RecoveryCodesIssued:
    """Plaintext codes, returned exactly once per generation."""

    codes: list[str]


class MfaService:
    """Second-factor lifecycle for one user's account."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        verify_limiter: Any | None = None,
    ) -> None:
        self._session = session
        self._limiter = verify_limiter

    # ------------------------------------------------------------------ #
    # Enrollment                                                           #
    # ------------------------------------------------------------------ #

    async def begin_enrollment(self, user: UserAccount) -> EnrollmentStarted:
        """Stage an encrypted pending secret (inactive until verified)."""
        row = await self._user_row(user.id)
        if row.mfa_enabled:
            raise MfaConflictError("MFA is already enabled for this account.")
        replacing = row.mfa_secret_encrypted is not None
        secret = generate_secret()
        try:
            row.mfa_secret_encrypted = encrypt_totp_secret(secret)
        except MfaSecretsNotConfiguredError as exc:
            raise MfaNotConfiguredError() from exc
        await self._session.flush()
        audit = AuditService(self._session)
        await audit.record(
            action_code=ACTION_MFA_SECRET_REPLACED if replacing else ACTION_MFA_ENROLL_STARTED,
            entity_type="user",
            entity_id=user.id,
            metadata_json={},
            actor_user_id=user.id,
        )
        return EnrollmentStarted(
            provisioning_uri=provisioning_uri(secret, account=user.email),
            secret=secret,
        )

    async def verify_enrollment(self, user: UserAccount, code: str) -> RecoveryCodesIssued:
        """Activate MFA after a correct code; issue recovery codes once."""
        _validate_code_shape(code)
        row = await self._user_row(user.id)
        if row.mfa_enabled:
            raise MfaConflictError("MFA is already enabled for this account.")
        if not row.mfa_secret_encrypted:
            raise InvalidMfaError("No pending MFA enrollment for this account.")
        try:
            secret = decrypt_totp_secret(row.mfa_secret_encrypted)
        except MfaSecretsNotConfiguredError as exc:
            raise MfaNotConfiguredError() from exc
        await self._check_limit(user.id)
        if not verify_code(secret, code.strip()):
            raise NotAuthenticatedError()
        row.mfa_enabled = True
        await self._session.flush()
        codes = await self._replace_recovery_codes(user.id)
        audit = AuditService(self._session)
        await audit.record(
            action_code=ACTION_MFA_ENABLED,
            entity_type="user",
            entity_id=user.id,
            metadata_json={},
            actor_user_id=user.id,
        )
        await audit.record(
            action_code=ACTION_MFA_RECOVERY_GENERATED,
            entity_type="user",
            entity_id=user.id,
            metadata_json={"count": len(codes.codes)},
            actor_user_id=user.id,
        )
        return codes

    async def status(self, user: UserAccount) -> dict[str, object]:
        """Enrollment state (never any secret material)."""
        row = await self._user_row(user.id)
        return {"enabled": bool(row.mfa_enabled)}

    # ------------------------------------------------------------------ #
    # Challenge verification (post-password second factor)                 #
    # ------------------------------------------------------------------ #

    async def verify_challenge(self, user_id: uuid.UUID, code: str) -> UserAccount:
        """Consume TOTP or a recovery code; return the account on success.

        Malformed codes are 400 (no account state revealed); well-formed
        but wrong codes are 401 (identical to login failures). Recovery
        codes are single-use: consumed atomically with success.
        """
        from src.domain.users.user_service import UserAccount as Account
        from src.infrastructure.database.repositories.user_repository import UserRepository

        _validate_code_shape(code)
        await self._check_limit(user_id)
        user = await UserRepository(self._session).get_by_id(user_id)
        if user is None or not user.is_active or not user.mfa_enabled:
            await self._audit_challenge(user_id, success=False)
            raise NotAuthenticatedError()
        clean = code.strip()
        if user.mfa_secret_encrypted:
            try:
                secret = decrypt_totp_secret(user.mfa_secret_encrypted)
            except MfaSecretsNotConfiguredError as exc:
                raise MfaNotConfiguredError() from exc
            step = matching_step(secret, clean)
            if step is not None:
                if await self._consume_totp_step(user.id, step):
                    await self._audit_challenge(user_id, success=True)
                    return Account(
                        id=user.id,
                        email=user.email,
                        created_at=user.created_at,
                        firebase_uid=user.firebase_uid,
                        mfa_enabled=True,
                    )
                await self._audit_challenge(user_id, success=False)
                raise NotAuthenticatedError()
        if await self._consume_recovery_code(user.id, clean):
            await self._audit_challenge(user_id, success=True)
            await AuditService(self._session).record(
                action_code=ACTION_MFA_RECOVERY_USED,
                entity_type="user",
                entity_id=user.id,
                metadata_json={},
                actor_user_id=user.id,
            )
            return Account(
                id=user.id,
                email=user.email,
                created_at=user.created_at,
                firebase_uid=user.firebase_uid,
                mfa_enabled=True,
            )
        await self._audit_challenge(user_id, success=False)
        raise NotAuthenticatedError()

    # ------------------------------------------------------------------ #
    # Disable / regenerate (strong re-authentication)                      #
    # ------------------------------------------------------------------ #

    async def disable(self, user: UserAccount, *, password: str, code: str) -> None:
        """Disable MFA: current password AND (TOTP or recovery code).

        Both factors are required so a bare session hijack cannot strip
        the second factor, while a user who lost the authenticator can
        still recover with password + recovery code.
        """
        from src.domain.users.user_service import UserService

        _validate_password_shape(password)
        _validate_code_shape(code)
        await UserService(self._session).authenticate(user.email, password)
        row = await self._user_row(user.id)
        if not row.mfa_enabled:
            raise InvalidMfaError("MFA is not enabled for this account.")
        clean = code.strip()
        totp_ok = False
        if row.mfa_secret_encrypted:
            try:
                step = matching_step(decrypt_totp_secret(row.mfa_secret_encrypted), clean)
            except MfaSecretsNotConfiguredError as exc:
                raise MfaNotConfiguredError() from exc
            totp_ok = step is not None and await self._consume_totp_step(user.id, step)
        if not totp_ok and not await self._consume_recovery_code(user.id, clean):
            raise NotAuthenticatedError()
        row.mfa_enabled = False
        row.mfa_secret_encrypted = None
        await self._delete_recovery_codes(user.id)
        await self._session.flush()
        await AuditService(self._session).record(
            action_code=ACTION_MFA_DISABLED,
            entity_type="user",
            entity_id=user.id,
            metadata_json={},
            actor_user_id=user.id,
        )

    async def regenerate_recovery_codes(
        self, user: UserAccount, *, totp_code: str
    ) -> RecoveryCodesIssued:
        """Replace all recovery codes (authed session + current TOTP)."""
        _validate_code_shape(totp_code)
        row = await self._user_row(user.id)
        if not row.mfa_enabled or not row.mfa_secret_encrypted:
            raise InvalidMfaError("MFA is not enabled for this account.")
        try:
            secret = decrypt_totp_secret(row.mfa_secret_encrypted)
        except MfaSecretsNotConfiguredError as exc:
            raise MfaNotConfiguredError() from exc
        await self._check_limit(user.id)
        step = matching_step(secret, totp_code.strip())
        if step is None or not await self._consume_totp_step(user.id, step):
            raise NotAuthenticatedError()
        codes = await self._replace_recovery_codes(user.id)
        await AuditService(self._session).record(
            action_code=ACTION_MFA_RECOVERY_REGENERATED,
            entity_type="user",
            entity_id=user.id,
            metadata_json={"count": len(codes.codes)},
            actor_user_id=user.id,
        )
        return codes

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    async def _user_row(self, user_id: uuid.UUID) -> Any:
        from src.infrastructure.database.models import User

        row = await self._session.get(User, user_id)
        if row is None:
            raise NotAuthenticatedError()
        return row

    async def _check_limit(self, user_id: uuid.UUID) -> None:
        if self._limiter is None:
            return
        if not await self._limiter.try_admit(str(user_id)):
            raise MfaRateLimitedError()

    async def _audit_challenge(self, user_id: uuid.UUID, *, success: bool) -> None:
        await AuditService(self._session).record(
            action_code=ACTION_MFA_CHALLENGE_SUCCESS if success else ACTION_MFA_CHALLENGE_FAILURE,
            entity_type="user",
            entity_id=user_id,
            metadata_json={},
            actor_user_id=user_id,
        )

    async def _replace_recovery_codes(self, user_id: uuid.UUID) -> RecoveryCodesIssued:
        from src.infrastructure.database.models import MfaRecoveryCode

        await self._delete_recovery_codes(user_id)
        codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
        for code in codes:
            self._session.add(MfaRecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code)))
        await self._session.flush()
        return RecoveryCodesIssued(codes=codes)

    async def _delete_recovery_codes(self, user_id: uuid.UUID) -> None:
        from sqlalchemy import delete

        from src.infrastructure.database.models import MfaRecoveryCode

        await self._session.execute(
            delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id)
        )

    async def _consume_totp_step(self, user_id: uuid.UUID, step: int) -> bool:
        """Record one TOTP step use; False when already spent (replay).

        The unique (user, step) row is the single-use guard: a racing
        duplicate loses the insert and fails closed. Only step counters
        persist — never codes.
        """
        from sqlalchemy.exc import IntegrityError

        from src.infrastructure.database.models import MfaTotpUse

        try:
            async with self._session.begin_nested():
                self._session.add(MfaTotpUse(user_id=user_id, time_step=step))
                await self._session.flush()
        except IntegrityError:
            return False
        return True

    async def _consume_recovery_code(self, user_id: uuid.UUID, code: str) -> bool:
        """Atomically consume one unused code (single-use enforced here).

        Rows lock (FOR UPDATE) so concurrent verifications serialize:
        exactly one consumer wins, the loser sees no unused match.
        """
        from sqlalchemy import select

        from src.infrastructure.database.models import MfaRecoveryCode

        rows = (
            (
                await self._session.execute(
                    select(MfaRecoveryCode)
                    .where(
                        MfaRecoveryCode.user_id == user_id,
                        MfaRecoveryCode.used_at.is_(None),
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            if hmac.compare_digest(row.code_hash, hash_recovery_code(code)):
                row.used_at = datetime.now(UTC)
                await self._session.flush()
                return True
        return False


def _validate_code_shape(code: object) -> str:
    """Codes are short text (1..32 chars); shape failures are 400."""
    if not isinstance(code, str):
        raise InvalidMfaError("Code must be text.")
    clean = code.strip()
    if not clean or len(code) > 32 or "\x00" in code:
        raise InvalidMfaError("Code must be 1..32 characters.")
    return clean


def _validate_password_shape(password: object) -> str:
    if not isinstance(password, str) or not password or len(password) > 128:
        raise InvalidMfaError("Password must be text (max 128 chars).")
    return password


__all__ = ["EnrollmentStarted", "MfaService", "RecoveryCodesIssued"]

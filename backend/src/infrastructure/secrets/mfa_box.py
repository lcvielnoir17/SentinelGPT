"""MFA secret encryption (Fernet, M11 pattern reuse).

Mirrors the webhook secret-box contract: TOTP secrets are encrypted
at rest with a Fernet key held in ``MFA_SECRET_KEY`` — a
database-only compromise never exposes second factors. An absent or
malformed key disables MFA loudly (503) instead of falling back to
plaintext. Recovery-code hashing lives alongside (one-way: codes are
verified, never decrypted).
"""

from __future__ import annotations

import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken


class MfaSecretsNotConfiguredError(Exception):
    """MFA_SECRET_KEY is missing or not a valid Fernet key."""


RECOVERY_CODE_COUNT = 10
RECOVERY_HASH_DOMAIN = "sgpt-mfa-recovery-v1"


def _fernet() -> Fernet:
    from src.config.settings import get_settings

    raw = (get_settings().mfa_secret_key or "").strip()
    try:
        return Fernet(raw.encode())
    except Exception as exc:
        raise MfaSecretsNotConfiguredError("MFA requires a valid MFA_SECRET_KEY") from exc


def encrypt_totp_secret(plaintext: str) -> str:
    """Encrypt one TOTP secret for storage."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_totp_secret(ciphertext: str) -> str:
    """Recover a TOTP secret for verification (verify path only)."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise MfaSecretsNotConfiguredError(
            "stored MFA secret cannot be decrypted with MFA_SECRET_KEY"
        ) from exc


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Fresh cryptographically random recovery codes (shown once)."""
    return [secrets.token_hex(5) for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    """One-way hash for storage (domain-separated SHA-256)."""
    return hashlib.sha256(f"{RECOVERY_HASH_DOMAIN}|{code}".encode()).hexdigest()


__all__ = [
    "RECOVERY_CODE_COUNT",
    "MfaSecretsNotConfiguredError",
    "decrypt_totp_secret",
    "encrypt_totp_secret",
    "generate_recovery_codes",
    "hash_recovery_code",
]

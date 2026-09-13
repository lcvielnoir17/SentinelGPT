"""Webhook secret box: Fernet encryption for per-webhook HMAC secrets.

Webhook signing needs the raw secret at send time, so hashing (like
passwords) cannot work. Secrets are encrypted at rest with a Fernet key
held in ``WEBHOOK_SECRET_KEY`` — a database-only compromise never
exposes signing capability. An absent or malformed key disables webhook
creation loudly (503) instead of falling back to plaintext.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class WebhookSecretsNotConfiguredError(Exception):
    """WEBHOOK_SECRET_KEY is missing or not a valid Fernet key."""


def _fernet() -> Fernet:
    from src.config.settings import get_settings

    raw = (get_settings().webhook_secret_key or "").strip()
    try:
        return Fernet(raw.encode())
    except Exception as exc:
        raise WebhookSecretsNotConfiguredError(
            "webhook creation requires a valid WEBHOOK_SECRET_KEY"
        ) from exc


def encrypt_secret(plaintext: str) -> str:
    """Encrypt one webhook HMAC secret for storage."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Recover a webhook HMAC secret for signing (send path only)."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise WebhookSecretsNotConfiguredError(
            "stored webhook secret cannot be decrypted with WEBHOOK_SECRET_KEY"
        ) from exc


def generate_secret() -> str:
    """Fresh 32-byte random HMAC secret (hex-encoded, shown once)."""
    import secrets

    return secrets.token_hex(32)

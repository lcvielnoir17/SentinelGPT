"""CI bearer tokens: generation, parsing, hashing, verification (M10).

Token format (all three parts required)::

    sgptci_<credential-uuid-hex>_<43-char urlsafe secret>

* the ``sgptci_`` prefix marks the credential family for operators;
* the embedded credential id gives an indexed lookup (no table scan,
  no enumeration oracle beyond unguessable UUIDs);
* the 256-bit secret is verified with a constant-time comparison
  against a SHA-256 hash with domain separation.

Only the hash is ever stored. The 256-bit secret makes offline brute
force infeasible, so no server-side pepper is needed (documented
choice, not an omission). Secrets never reach logs, audits, or
API responses — call sites pass them as transient arguments only.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

TOKEN_PREFIX = "sgptci_"
HASH_DOMAIN = "sgpt-ci-credential-v1"
KEY_PREFIX_LABEL = "sgptci_"


def generate_secret() -> str:
    """Fresh 256-bit urlsafe secret for one credential."""
    return secrets.token_urlsafe(32)


def build_plaintext(credential_id: uuid.UUID, secret: str) -> str:
    """Assemble the bearer token shown exactly once at creation/rotation."""
    return f"{TOKEN_PREFIX}{credential_id.hex}_{secret}"


def key_prefix_for(secret: str) -> str:
    """Short operational identifier derived from the secret (safe to store).

    Lets operators correlate audit rows and support requests without
    ever handling secret material.
    """
    return f"{KEY_PREFIX_LABEL}{hashlib.sha256(secret.encode()).hexdigest()[:8]}"


def hash_secret(secret: str) -> str:
    """One-way hash for storage (domain-separated SHA-256)."""
    return hashlib.sha256(f"{HASH_DOMAIN}|{secret}".encode()).hexdigest()


def parse_plaintext(raw: str) -> tuple[uuid.UUID, str] | None:
    """Split a bearer token into (credential id, secret); None if malformed."""
    if not isinstance(raw, str) or not raw.startswith(TOKEN_PREFIX):
        return None
    rest = raw[len(TOKEN_PREFIX) :]
    credential_hex, separator, secret = rest.partition("_")
    if not separator or not secret:
        return None
    try:
        credential_id = uuid.UUID(hex=credential_hex)
    except ValueError:
        return None
    return credential_id, secret


def verify_secret(secret: str, secret_hash: str) -> bool:
    """Constant-time secret check."""
    if not secret or not secret_hash:
        return False
    return hmac.compare_digest(hash_secret(secret), secret_hash)


__all__ = [
    "TOKEN_PREFIX",
    "HASH_DOMAIN",
    "build_plaintext",
    "generate_secret",
    "hash_secret",
    "key_prefix_for",
    "parse_plaintext",
    "verify_secret",
]

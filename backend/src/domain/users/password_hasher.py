"""Password hashing for the identity domain (SRS Chapter 11, Section 8).

Uses Argon2id via argon2-cffi — the SRS-preferred algorithm. No reversible
encoding of passwords under any circumstance.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Library defaults are Argon2id with sane memory/time cost parameters.
_hasher = PasswordHasher()


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with Argon2id (includes per-hash salt)."""
    return _hasher.hash(plaintext)


def verify_password(password_hash: str, plaintext: str) -> bool:
    """Constant-time verification; returns False on any mismatch/malformation."""
    try:
        return _hasher.verify(password_hash, plaintext)
    except (VerifyMismatchError, InvalidHashError):
        return False

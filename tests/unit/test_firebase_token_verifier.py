"""Unit tests for Firebase ID token verification (ADR-0010).

The verifier's only network dependency is Google's public JWK endpoint; a
fake JWKS client backed by a locally generated RSA key keeps every test
offline. Tokens are minted with the real RS256 signing path so signature,
audience, issuer, and expiry rules are exercised end-to-end.
"""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.domain.errors import FirebaseTokenInvalidError
from src.domain.users.firebase_token_service import FirebaseTokenVerifier

PROJECT_ID = "demo-sentinelgpt"

# A second key so wrong-signature tokens can be minted without reusing the
# trusted key material.
TRUSTED_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ROGUE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _FakeSigningKey:
    """Mirrors the ``.key`` attribute jwt.PyJWKClient exposes."""

    def __init__(self, key: object) -> None:
        self.key = key


class _FakeJwksClient:
    """Offline stand-in for jwt.PyJWKClient serving one trusted RSA key."""

    def __init__(self, key: object) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, _token: str) -> _FakeSigningKey:
        return _FakeSigningKey(self._key)


def _pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _mint_token(claims: dict[str, object], key: rsa.RSAPrivateKey = TRUSTED_KEY) -> str:
    return jwt.encode(claims, _pem(key), algorithm="RS256")


def _valid_claims(**overrides: object) -> dict[str, object]:
    now = int(datetime.now(UTC).timestamp())
    claims: dict[str, object] = {
        "iss": f"https://securetoken.google.com/{PROJECT_ID}",
        "aud": PROJECT_ID,
        "sub": "firebase-uid-123",
        "iat": now,
        "exp": now + 3600,
        "email": "analyst@example.com",
        "email_verified": True,
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def verifier() -> FirebaseTokenVerifier:
    return FirebaseTokenVerifier(PROJECT_ID, jwks_client=_FakeJwksClient(TRUSTED_KEY.public_key()))


def test_valid_token_yields_verified_identity(verifier: FirebaseTokenVerifier) -> None:
    identity = verifier.verify(_mint_token(_valid_claims()))
    assert identity.uid == "firebase-uid-123"
    assert identity.email == "analyst@example.com"
    assert identity.email_verified is True


def test_wrong_key_signature_rejected(verifier: FirebaseTokenVerifier) -> None:
    token = _mint_token(_valid_claims(), key=ROGUE_KEY)
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(token)


def test_wrong_audience_rejected(verifier: FirebaseTokenVerifier) -> None:
    token = _mint_token(_valid_claims(aud="other-project"))
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(token)


def test_wrong_issuer_rejected(verifier: FirebaseTokenVerifier) -> None:
    token = _mint_token(_valid_claims(iss="https://evil.example.com/firebase"))
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(token)


def test_expired_token_rejected(verifier: FirebaseTokenVerifier) -> None:
    now = int(datetime.now(UTC).timestamp())
    token = _mint_token(_valid_claims(iat=now - 7200, exp=now - 3600))
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(token)


def test_issued_in_future_beyond_leeway_rejected(
    verifier: FirebaseTokenVerifier,
) -> None:
    now = int(datetime.now(UTC).timestamp())
    token = _mint_token(
        _valid_claims(iat=now + int(timedelta(minutes=30).total_seconds()), exp=now + 7200)
    )
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(token)


def test_missing_sub_rejected(verifier: FirebaseTokenVerifier) -> None:
    claims = _valid_claims()
    del claims["sub"]
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(_mint_token(claims))


def test_null_sub_rejected(verifier: FirebaseTokenVerifier) -> None:
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(_mint_token(_valid_claims(sub=None)))


def test_empty_sub_rejected(verifier: FirebaseTokenVerifier) -> None:
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(_mint_token(_valid_claims(sub="")))


def test_missing_exp_rejected(verifier: FirebaseTokenVerifier) -> None:
    claims = _valid_claims()
    del claims["exp"]
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(_mint_token(claims))


@pytest.mark.parametrize("bad", ["", "not-a-token", "a.b", "a.b.c", "x" * 5000, ".."])
def test_malformed_tokens_rejected(verifier: FirebaseTokenVerifier, bad: str) -> None:
    with pytest.raises(FirebaseTokenInvalidError):
        verifier.verify(bad)


def test_legacy_string_email_verified_flags(verifier: FirebaseTokenVerifier) -> None:
    verified = verifier.verify(_mint_token(_valid_claims(email_verified="1")))
    unverified = verifier.verify(_mint_token(_valid_claims(email_verified="0")))
    assert verified.email_verified is True
    assert unverified.email_verified is False


def test_token_without_email_yields_none_email(verifier: FirebaseTokenVerifier) -> None:
    claims = _valid_claims()
    del claims["email"]
    del claims["email_verified"]
    identity = verifier.verify(_mint_token(claims))
    assert identity.email is None
    assert identity.email_verified is False

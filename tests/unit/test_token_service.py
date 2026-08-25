"""Unit tests for access-token signing/verification."""

import uuid

import pytest

from src.domain.errors import NotAuthenticatedError
from src.domain.users.token_service import create_access_token, decode_access_token

SECRET = "unit-test-secret-key-with-at-least-32-characters"
ALGORITHM = "HS256"


def _make_token(user_id: uuid.UUID | None = None, minutes: int = 15) -> tuple[str, uuid.UUID]:
    uid = user_id or uuid.uuid4()
    token = create_access_token(
        user_id=uid,
        secret_key=SECRET,
        algorithm=ALGORITHM,
        expires_in_minutes=minutes,
    )
    return token, uid


def test_round_trip_returns_user_id() -> None:
    token, uid = _make_token()
    assert decode_access_token(token, secret_key=SECRET, algorithm=ALGORITHM) == uid


def test_expired_token_is_unauthenticated() -> None:
    token, _ = _make_token(minutes=-1)
    with pytest.raises(NotAuthenticatedError):
        decode_access_token(token, secret_key=SECRET, algorithm=ALGORITHM)


def test_tampered_payload_is_unauthenticated() -> None:
    import jwt

    token, _ = _make_token()
    header, payload, signature = token.split(".")
    forged = jwt.encode({"sub": str(uuid.uuid4())}, SECRET, algorithm=ALGORITHM).split(".")[1]
    with pytest.raises(NotAuthenticatedError):
        decode_access_token(
            f"{header}.{forged}.{signature}", secret_key=SECRET, algorithm=ALGORITHM
        )


def test_wrong_secret_is_unauthenticated() -> None:
    token, _ = _make_token()
    with pytest.raises(NotAuthenticatedError):
        decode_access_token(
            token, secret_key="another-secret-key-with-at-least-32-chars!", algorithm=ALGORITHM
        )


def test_garbage_token_is_unauthenticated() -> None:
    with pytest.raises(NotAuthenticatedError):
        decode_access_token("not-a-jwt", secret_key=SECRET, algorithm=ALGORITHM)

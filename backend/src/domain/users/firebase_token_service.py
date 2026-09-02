"""Firebase ID token verification (ADR-0010).

Implements Google's documented verification algorithm for Firebase ID
tokens using the already-locked PyJWT + ``cryptography`` stack — no
service-account credential is needed to *verify* tokens (only the
project ID), so the API container never holds Firebase admin secrets for
authentication:

1. resolve the token's signing key from Google's public JWKs
   (cached by ``jwt.PyJWKClient``);
2. verify the RS256 signature;
3. verify ``aud`` == Firebase project ID and ``iss`` ==
   ``https://securetoken.google.com/<project-id>``;
4. verify ``exp`` (with the 5-minute clock skew Google allows);
5. require a non-empty ``sub`` claim (the Firebase UID).

The result is a :class:`FirebaseIdentity` carrying the verified UID and
(email, email_verified) — the ONLY source of identity data the bridge
trusts. Client-supplied user IDs are never consulted anywhere.

``verify`` is synchronous (one blocking JWKS fetch, then cached); the API
endpoint offloads it to a worker thread. Tests inject a fake JWK client
so the suite never touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import jwt
from jwt import PyJWKClient

from src.domain.errors import FirebaseTokenInvalidError

FIREBASE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
)
ISSUER_TEMPLATE = "https://securetoken.google.com/{project_id}"
# Google's own verification guidance allows modest clock skew.
CLOCK_SKEW = timedelta(minutes=5)
MAX_TOKEN_LENGTH = 4096


@dataclass(frozen=True)
class FirebaseIdentity:
    """Verified Firebase identity extracted from an ID token."""

    uid: str
    email: str | None
    email_verified: bool


def _as_bool(value: Any) -> bool:
    """Accept the boolean and legacy ``"1"``/``"0"`` encodings."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value == "1"
    return False


class FirebaseTokenVerifier:
    """Verifies Firebase ID tokens against Google's public keys."""

    def __init__(self, project_id: str, *, jwks_client: Any | None = None) -> None:
        if not project_id:
            raise ValueError("FirebaseTokenVerifier requires a Firebase project ID")
        self._project_id = project_id
        self._issuer = ISSUER_TEMPLATE.format(project_id=project_id)
        # The JWK client performs blocking HTTP; the endpoint runs verify()
        # inside a worker thread. Injectable for offline tests.
        self._jwks: Any = jwks_client if jwks_client is not None else PyJWKClient(FIREBASE_JWKS_URL)

    def verify(self, token: str) -> FirebaseIdentity:
        """Validate an ID token; raises FirebaseTokenInvalidError on any failure."""
        if not token or len(token) > MAX_TOKEN_LENGTH or token.count(".") != 2:
            raise FirebaseTokenInvalidError()
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._project_id,
                issuer=self._issuer,
                leeway=CLOCK_SKEW,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise FirebaseTokenInvalidError() from exc
        except Exception as exc:  # noqa: BLE001 - any JWKS/network failure is invalid-token
            raise FirebaseTokenInvalidError() from exc

        uid = claims.get("sub")
        if not isinstance(uid, str) or not uid or len(uid) > 128:
            raise FirebaseTokenInvalidError()

        email_raw = claims.get("email")
        email = email_raw if isinstance(email_raw, str) and email_raw else None
        return FirebaseIdentity(
            uid=uid,
            email=email,
            email_verified=_as_bool(claims.get("email_verified")),
        )

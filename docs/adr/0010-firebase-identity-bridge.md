# ADR-0010: Firebase Authentication identity bridge

**Status:** Implemented (2026-09-03)

## Context

The Ideathon requires user authentication via Firebase. SentinelGPT already
ships a complete, security-reviewed session system: HttpOnly cookie-based
access JWTs, opaque server-tracked refresh credentials with rotation and
family revocation, argon2id password hashing, and a CSRF header on
session-changing routes (SRS Ch2 §9, Ch5 §2, Ch11 §8).

## Decision

**Bridge, not replace.** Firebase issues identities; SentinelGPT keeps
authorizing them.

1. The frontend signs in with Firebase (Google popup) and obtains an ID
   token.
2. `POST /api/v1/auth/firebase` verifies the ID token **server-side**
   against Google's public JWKs (RS256 signature, `aud` == project,
   `iss` == `https://securetoken.google.com/<project>`, `exp` with the
   documented 5-minute leeway, non-empty `sub`). Verification needs only
   the project ID — no Firebase admin credential is required for
   authentication, so no admin secret sits in the API container.
3. The verified UID maps onto the canonical SentinelGPT `user` row
   (migration 0007 adds a unique `user.firebase_uid`):
   * a `firebase_uid` match wins;
   * otherwise an existing local account with the **same verified email**
     is linked (Firebase asserts `email_verified`; unverified addresses are
     never used for linkage or addressing);
   * otherwise a federated account is provisioned (`password_hash` NULL —
     it can never log in with a password).
4. The endpoint then issues the **existing** access/refresh cookie pair.
   Every downstream authorization decision continues to key on the
   canonical `user.id` via `get_current_user`.

Firebase UID is login plumbing; the UUID account is the identity.

## Alternatives considered

* **Replace** the session system with Firebase session cookies — would
  discard refresh rotation/reuse detection, CSRF header, and the fail-fast
  settings contract; destructive for no functional gain.
* **firebase-admin SDK** — pulls the entire Admin surface (Cloud Storage,
  Realtime Database, messaging) into the image to use one token-verify
  function, and its verification requires a service-account credential.
  PyJWT + Google's public JWKs implements the same documented algorithm.

## Consequences

* Existing local email/password auth keeps working unchanged; one account
  can hold both login paths.
* The endpoint returns 503 `FEATURE_DISABLED` when `FIREBASE_PROJECT_ID`
  is unset, and one generic 401 for every token failure (no verification
  detail leaks).
* Conversations (ADR-0011) scope their Firestore paths by the verified
  Firebase UID, which is why the bridge stores it.

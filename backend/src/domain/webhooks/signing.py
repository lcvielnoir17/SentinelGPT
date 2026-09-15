"""Webhook payload signing (HMAC-SHA256, pure functions).

Every delivery carries three headers so receivers can authenticate,
deduplicate, and bound replay:

* ``X-SentinelGPT-Signature: sha256=<hex>`` — HMAC over a canonical
  envelope (``sgpt-webhook-v1\\n<timestamp>\\n<event-id>\\n`` +
  exact request body bytes) with the per-webhook secret, so the
  timestamp and event id are authenticated alongside the body;
* ``X-SentinelGPT-Event-Id`` — the deterministic event id (receiver
  dedupe key, covered by the signature);
* ``X-SentinelGPT-Timestamp`` — unix seconds at sign time (covered by
  the signature; receiver replay-window check via
  :func:`verify_timestamp_fresh`, 5-minute tolerance default).

:func:`sign_payload` returns the signature and timestamp headers; the
sender attaches the event-id header alongside them.
"""

from __future__ import annotations

import hashlib
import hmac

SIGNATURE_HEADER = "X-SentinelGPT-Signature"
EVENT_ID_HEADER = "X-SentinelGPT-Event-Id"
TIMESTAMP_HEADER = "X-SentinelGPT-Timestamp"
SIGNATURE_PREFIX = "sha256="
SIGNING_VERSION = "sgpt-webhook-v1"
REPLAY_TOLERANCE_SECONDS = 300


def _signed_content(body: bytes, *, timestamp: int, event_id: str) -> bytes:
    """Canonical envelope: every authenticated field, unambiguous framing."""
    return (
        SIGNING_VERSION.encode("ascii")
        + b"\n"
        + str(timestamp).encode("ascii")
        + b"\n"
        + event_id.encode("utf-8")
        + b"\n"
        + body
    )


def sign_payload(secret: str, body: bytes, *, timestamp: int, event_id: str) -> dict[str, str]:
    """Sign one delivery; returns the signature and timestamp headers."""
    digest = hmac.new(
        secret.encode(),
        _signed_content(body, timestamp=timestamp, event_id=event_id),
        hashlib.sha256,
    ).hexdigest()
    return {
        SIGNATURE_HEADER: f"{SIGNATURE_PREFIX}{digest}",
        TIMESTAMP_HEADER: str(timestamp),
    }


def verify_signature(
    secret: str, body: bytes, signature: str, *, timestamp: int, event_id: str
) -> bool:
    """Constant-time check over body + timestamp + event id."""
    if not signature.startswith(SIGNATURE_PREFIX):
        return False
    expected = hmac.new(
        secret.encode(),
        _signed_content(body, timestamp=timestamp, event_id=event_id),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature[len(SIGNATURE_PREFIX) :])


def verify_timestamp_fresh(
    timestamp: int, *, now_unix: int, tolerance_seconds: int = REPLAY_TOLERANCE_SECONDS
) -> bool:
    """True when the signed timestamp is inside the replay window."""
    if tolerance_seconds < 0:
        return False
    return abs(now_unix - timestamp) <= tolerance_seconds


__all__ = [
    "REPLAY_TOLERANCE_SECONDS",
    "SIGNATURE_HEADER",
    "EVENT_ID_HEADER",
    "SIGNING_VERSION",
    "TIMESTAMP_HEADER",
    "SIGNATURE_PREFIX",
    "sign_payload",
    "verify_signature",
    "verify_timestamp_fresh",
]

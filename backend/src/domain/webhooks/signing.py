"""Webhook payload signing (HMAC-SHA256, pure functions).

Every delivery carries three headers so receivers can authenticate,
deduplicate, and bound replay:

* ``X-SentinelGPT-Signature: sha256=<hex>`` — HMAC over the exact
  request body bytes with the per-webhook secret;
* ``X-SentinelGPT-Event-Id`` — the deterministic event id (receiver
  dedupe key);
* ``X-SentinelGPT-Timestamp`` — unix seconds at sign time (receiver
  replay-window check; 5-minute tolerance recommended).

:func:`sign_payload` returns the signature and timestamp headers; the
sender attaches the event-id header alongside them so the pure signing
core never needs to know the event envelope.
"""

from __future__ import annotations

import hashlib
import hmac

SIGNATURE_HEADER = "X-SentinelGPT-Signature"
EVENT_ID_HEADER = "X-SentinelGPT-Event-Id"
TIMESTAMP_HEADER = "X-SentinelGPT-Timestamp"
SIGNATURE_PREFIX = "sha256="


def sign_payload(secret: str, body: bytes, *, timestamp: int) -> dict[str, str]:
    """Sign one delivery body; returns the three headers to attach."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        SIGNATURE_HEADER: f"{SIGNATURE_PREFIX}{digest}",
        TIMESTAMP_HEADER: str(timestamp),
    }


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    """Constant-time signature check (receivers + tests)."""
    if not signature.startswith(SIGNATURE_PREFIX):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature[len(SIGNATURE_PREFIX) :])


__all__ = [
    "SIGNATURE_HEADER",
    "EVENT_ID_HEADER",
    "TIMESTAMP_HEADER",
    "SIGNATURE_PREFIX",
    "sign_payload",
    "verify_signature",
]

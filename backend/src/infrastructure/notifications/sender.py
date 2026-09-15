"""Outbound webhook delivery (single reviewed HTTP-capable module).

This is the ONLY host-side module allowed to open HTTP connections to
operator-configured destinations (see the static boundary guard's
reviewed exception). Confinement rules encoded here, not just
documented:

* destinations re-validated immediately before connect (DNS-rebinding
  defense; validation failures are terminal, never retried);
* https only (validated upstream too — defense in depth);
* redirects disabled (any 3xx is a terminal failure, never followed to
  a potentially private destination);
* bounded timeout per webhook, no response-body retention;
* secrets arrive as arguments (decrypted by the caller), are never
  logged, and never persist here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from src.domain.webhooks.signing import (
    EVENT_ID_HEADER,
    TIMESTAMP_HEADER,
    sign_payload,
)

RETRYABLE_STATUS_FLOOR = 500


@dataclass(frozen=True)
class DeliveryOutcome:
    """One send attempt: delivered, retryable, or terminally failed."""

    delivered: bool
    retryable: bool
    detail: str = ""
    status_code: int | None = None


def _now_unix() -> int:
    import time

    return int(time.time())


def build_signed_request(
    *,
    secret: str,
    event_id: str,
    payload: dict[str, Any],
    timestamp: int | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Canonical body + auth headers for one delivery attempt."""
    from src.domain.scanning.findings import dumps_stable

    body = dumps_stable(payload).encode("utf-8")
    moment = timestamp if timestamp is not None else _now_unix()
    headers = dict(sign_payload(secret, body, timestamp=moment, event_id=event_id))
    headers[EVENT_ID_HEADER] = event_id
    headers[TIMESTAMP_HEADER] = str(moment)
    headers["Content-Type"] = "application/json"
    return body, headers


async def send_delivery(
    *,
    url: str,
    secret: str,
    event_id: str,
    payload: dict[str, Any],
    timeout_seconds: int,
) -> DeliveryOutcome:
    """POST one signed delivery (redirects refused, timeouts bounded)."""
    from src.infrastructure.network.webhook_target import (
        InvalidWebhookUrlError,
        validate_webhook_url,
    )

    try:
        validate_webhook_url(url)
    except InvalidWebhookUrlError as exc:
        return DeliveryOutcome(delivered=False, retryable=False, detail=str(exc))

    body, headers = build_signed_request(secret=secret, event_id=event_id, payload=payload)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=float(timeout_seconds)
        ) as client:
            response = await client.post(url, content=body, headers=headers)
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        return DeliveryOutcome(
            delivered=False, retryable=True, detail=f"{type(exc).__name__}: delivery failed"
        )
    except httpx.HTTPError as exc:
        return DeliveryOutcome(
            delivered=False, retryable=False, detail=f"{type(exc).__name__}: delivery failed"
        )
    status = response.status_code
    if 200 <= status < 300:
        return DeliveryOutcome(delivered=True, retryable=False, status_code=status)
    if status in (301, 302, 303, 307, 308):
        return DeliveryOutcome(
            delivered=False,
            retryable=False,
            detail=f"redirect refused (HTTP {status}); webhooks never follow redirects",
            status_code=status,
        )
    if status >= RETRYABLE_STATUS_FLOOR:
        return DeliveryOutcome(
            delivered=False, retryable=True, detail=f"HTTP {status}", status_code=status
        )
    return DeliveryOutcome(
        delivered=False, retryable=False, detail=f"HTTP {status}", status_code=status
    )


__all__ = [
    "DeliveryOutcome",
    "build_signed_request",
    "send_delivery",
]

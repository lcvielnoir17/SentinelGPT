"""Webhook callback destination validation (separate trust boundary).

Callback URLs are operator-configured, but operators make mistakes and
DNS answers change: every destination is validated at creation time AND
re-validated immediately before each delivery (DNS-rebinding defense).
Rules:

* https scheme only (signed payloads must never travel plaintext);
* no embedded userinfo, no empty host, sane port;
* every resolved address must pass the shared IP admission policy
  (no loopback/private/link-local/multicast/reserved/metadata);
* resolution runs under a bounded timeout and fails closed.

Known residual: a sub-second TOCTOU between validation and connect
exists (no pinned-IP transport outside the scanner sandbox). It is
documented, not hidden: validation still defeats stable malicious DNS,
which is the realistic threat for callback configuration.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any

from src.domain.scanning.ip_policy import evaluate_ip

DEFAULT_RESOLVE_TIMEOUT_S = 5.0


class InvalidWebhookUrlError(ValueError):
    """A webhook callback URL failed destination validation."""


@dataclass(frozen=True)
class ValidatedWebhookTarget:
    """A webhook URL that passed destination validation."""

    url: str
    host: str
    port: int
    addresses: tuple[str, ...]


def _resolve_with_timeout(host: str, port: int, timeout_s: float) -> list[tuple[Any, ...]]:
    """Resolve A/AAAA records, bounded (fail closed on timeout)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        try:
            records = future.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError as exc:
            raise InvalidWebhookUrlError(f"DNS resolution timed out for {host!r}") from exc
        except socket.gaierror as exc:
            raise InvalidWebhookUrlError(f"DNS resolution failed for {host!r}: {exc}") from exc
    return [record[4] for record in records]


def validate_webhook_url(
    url: str, *, timeout_s: float = DEFAULT_RESOLVE_TIMEOUT_S
) -> ValidatedWebhookTarget:
    """Parse, resolve, and admission-check one callback URL."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError as exc:
        raise InvalidWebhookUrlError(f"unparseable webhook URL: {exc}") from exc
    if parts.scheme.lower() != "https":
        raise InvalidWebhookUrlError("webhook URL must use the https scheme")
    if parts.username or parts.password:
        raise InvalidWebhookUrlError("webhook URL must not embed credentials")
    host = parts.hostname or ""
    if not host:
        raise InvalidWebhookUrlError("webhook URL has no host")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise InvalidWebhookUrlError(f"webhook URL has an invalid port: {exc}") from exc
    if not 1 <= port <= 65535:
        raise InvalidWebhookUrlError("webhook URL port out of range")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        verdict = evaluate_ip(literal)
        if not verdict.allowed:
            raise InvalidWebhookUrlError(
                f"webhook IP is not an admissible destination: {verdict.reason}"
            )
        return ValidatedWebhookTarget(url=url, host=host, port=port, addresses=(str(literal),))

    sockaddr_list = _resolve_with_timeout(host, port, timeout_s)
    addresses: list[str] = []
    for sockaddr in sockaddr_list:
        ip_text = str(sockaddr[0])
        try:
            candidate = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise InvalidWebhookUrlError(f"unparseable DNS answer {ip_text!r}") from exc
        verdict = evaluate_ip(candidate)
        if not verdict.allowed:
            raise InvalidWebhookUrlError(
                f"webhook host resolves to an inadmissible address ({ip_text}: {verdict.reason})"
            )
        addresses.append(ip_text)
    if not addresses:
        raise InvalidWebhookUrlError(f"webhook host has no usable addresses: {host!r}")
    return ValidatedWebhookTarget(url=url, host=host, port=port, addresses=tuple(addresses))

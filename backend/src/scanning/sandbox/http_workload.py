"""Container-side HTTP workload program (ADR-0006).

This source is base64-injected into the established sandbox and executed via
``sandbox.run()`` as the unprivileged workload UID. It is the ONLY component
that touches the network for an HTTP scan attempt, so every byte it sends is
subject to the kernel OUTPUT chain installed from the validated binding.

Protocol (stdout, single line):

    SGPT/1 <json>     success: {status, headers, body_b64, truncated,
                                elapsed_ms, tls}
    SGPTERR/1 <json>  controlled failure: {kind, detail, tls}  (exit code 2)

The optional ``tls`` block is a passive description of the handshake the
workload already performed (success path) or a best-effort descriptive
handshake issued after a verification refusal (error path). It performs
NO HTTP exchange, trusts NOTHING (verify-off captures describe the
offending certificate; they never authorize anything), and is confined
to the same pinned destination, SNI, timeouts, and sandbox as the scan
itself. Absence of the block never fails the scan.

Security properties:

* The URL host IS the validated/pinned IP (v6 bracketed); the logical
  hostname rides ONLY in the Host header and the ``sni_hostname`` request
  extension — which httpcore feeds to SSL ``server_hostname``, driving both
  SNI and certificate identity checks. Verification is never disabled.
* Redirects are DISABLED here; hop decisions belong to the host-side
  orchestrator, which revalidates every destination and re-pins before any
  further exchange.
* Response bodies are stream-clamped at max_response_bytes.
"""

from __future__ import annotations

import base64
import json
import ssl
import sys
import time
from typing import Any

import httpx

SUCCESS_PREFIX = "SGPT/1 "
ERROR_PREFIX = "SGPTERR/1 "
_EXIT_CONTROLLED = 2
_EXIT_UNEXPECTED = 1


def _emit_error(kind: str, detail: str, tls: dict[str, Any] | None = None) -> int:
    payload = json.dumps({"kind": kind, "detail": detail[:500], "tls": tls})
    sys.stdout.write(ERROR_PREFIX + payload + "\n")
    sys.stdout.flush()
    return _EXIT_CONTROLLED


def _classify(exc: Exception) -> tuple[str, str]:
    import ssl

    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout", "connect timed out"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout", "read timed out"
    # Walk the FULL chained exception graph: httpx/httpcore may lose the
    # precise SSL error depending on where the handshake fails.
    stack: list[BaseException] = [exc]
    seen_ids: set[int] = set()
    while stack:
        current = stack.pop()
        if id(current) in seen_ids:
            continue
        seen_ids.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return "tls_error", "certificate verification failed"
        for chained in (current.__cause__, current.__context__):
            if chained is not None:
                stack.append(chained)
    cause = exc.__cause__ or exc
    if isinstance(
        exc,
        (
            httpx.ConnectError,
            httpx.RemoteProtocolError,
            httpx.LocalProtocolError,
            httpx.InvalidURL,
            httpx.UnsupportedProtocol,
        ),
    ):
        return "protocol_error", type(cause).__name__
    return "protocol_error", type(exc).__name__


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--spec-b64":
        print("usage: workload --spec-b64 <b64json>", file=sys.stderr)
        return _EXIT_UNEXPECTED
    try:
        spec = json.loads(base64.b64decode(argv[1]).decode())
    except Exception:  # noqa: BLE001 - malformed invocation is a hard stop
        print("unparseable spec", file=sys.stderr)
        return _EXIT_UNEXPECTED

    headers = [(str(k), str(v)) for k, v in spec.get("headers", [])]
    body = base64.b64decode(spec["body_b64"]) if spec.get("body_b64") else None
    max_bytes = int(spec["max_response_bytes"])

    started = time.monotonic()
    ca_path: str | None = None
    try:
        verify: bool | ssl.SSLContext = True
        ca_b64 = spec.get("ca_b64")
        if ca_b64:
            # Scan-scoped CA pinning: an explicitly supplied test/enterprise
            # CA is ADDED to default verification; validation itself is
            # never disabled. The file is created in a per-invocation secure
            # temp directory and unlinked before the exchange completes.
            import tempfile

            tmp_dir = tempfile.mkdtemp(prefix="sgpt-scan-")
            ca_path = f"{tmp_dir}/ca.pem"
            with open(ca_path, "wb") as fh:
                fh.write(base64.b64decode(ca_b64))
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(cafile=ca_path)
            verify = ctx

        with httpx.Client(
            verify=verify,
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=float(spec["connect_timeout_s"]),
                read=float(spec["read_timeout_s"]),
                write=10.0,
                pool=5.0,
            ),
        ) as client:
            request = client.build_request(
                spec["method"],
                spec["url"],
                headers=headers,
                content=body,
                extensions={"sni_hostname": spec["sni_hostname"]},
            )
            response = client.send(request, stream=True)
            try:
                chunks: list[bytes] = []
                received = 0
                truncated = False
                for chunk in response.iter_raw():
                    received += len(chunk)
                    if received >= max_bytes:
                        keep = max_bytes - (received - len(chunk))
                        chunks.append(chunk[:keep])
                        truncated = True
                        break
                    chunks.append(chunk)
                body_out = b"".join(chunks)
                status = response.status_code
                # .raw preserves DUPLICATE headers (critical for multiple
                # Set-Cookie lines); .items() would comma-merge them.
                resp_headers = [
                    [k.decode("latin-1"), v.decode("latin-1")] for k, v in response.headers.raw
                ]
            finally:
                response.close()
    except Exception as exc:  # noqa: BLE001 - mapped onto taxonomy below
        kind, detail = _classify(exc)
        tls_block: dict[str, Any] | None = None
        if kind == "tls_error":
            # Verification refused the chain: describe (never trust) the
            # presented certificate so the engine can tell expired /
            # mismatch / untrusted apart instead of lumping every refusal.
            tls_block = _describe_tls(spec, verify=False)
            if tls_block is not None:
                tls_block["verified"] = False
                tls_block["verify_error"] = detail[:200]
        return _emit_error(kind, detail, tls_block)
    finally:
        if ca_path is not None:
            import os
            import shutil

            with __import__("contextlib").suppress(OSError):
                shutil.rmtree(os.path.dirname(ca_path), ignore_errors=True)

    elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
    success_tls = _describe_tls(spec, verify=True) if _spec_scheme(spec) == "https" else None
    payload = json.dumps(
        {
            "status": status,
            "headers": resp_headers,
            "body_b64": base64.b64encode(body_out).decode(),
            "truncated": truncated,
            "elapsed_ms": elapsed_ms,
            "tls": success_tls,
        }
    )
    sys.stdout.write(SUCCESS_PREFIX + payload + "\n")
    sys.stdout.flush()
    return 0


def _spec_scheme(spec: dict[str, Any]) -> str:
    url = str(spec.get("url", ""))
    return url.split("://", 1)[0].lower() if "://" in url else ""


def _spec_host_port(spec: dict[str, Any]) -> tuple[str, int] | None:
    """Pinned destination from the spec URL (host is already a validated IP)."""
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(str(spec.get("url", "")))
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    default = 443 if _spec_scheme(spec) == "https" else 80
    try:
        port = parts.port or default
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def _cert_to_jsonable(cert: dict[str, Any]) -> dict[str, Any]:
    """Bounded JSON form of a peer certificate (public fields only)."""

    def _name(parts: object) -> str:
        chunks: list[str] = []
        if isinstance(parts, (list, tuple)):
            for seq in parts:
                if isinstance(seq, (list, tuple)):
                    for pair in seq:
                        if isinstance(pair, (list, tuple)) and len(pair) == 2:
                            chunks.append(f"{pair[0]}={pair[1]}")
        return ",".join(chunks)[:256]

    san: list[str] = []
    raw_san = cert.get("subjectAltName", ())
    if isinstance(raw_san, (list, tuple)):
        for entry in raw_san:
            if (
                isinstance(entry, (list, tuple))
                and len(entry) == 2
                and entry[0]
                in (
                    "DNS",
                    "IP Address",
                )
            ):
                san.append(str(entry[1])[:253])
                if len(san) >= 20:
                    break
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    return {
        "subject": _name(cert.get("subject", ())),
        "issuer": _name(cert.get("issuer", ())),
        "san": san,
        "not_before": str(not_before)[:64] if not_before else None,
        "not_after": str(not_after)[:64] if not_after else None,
    }


def _describe_tls(spec: dict[str, Any], *, verify: bool) -> dict[str, Any] | None:
    """Handshake-only TLS observation of the pinned destination.

    Opens ONE TCP+TLS handshake to the spec URL's host (the pinned IP),
    with SNI set to the validated hostname. Sends no HTTP bytes and
    closes immediately. ``verify=False`` DESCRIBES the presented chain
    without trusting it; the result feeds assessment only.
    Every failure mode returns None — telemetry never fails the scan.
    """
    import socket
    import ssl
    import tempfile

    endpoint = _spec_host_port(spec)
    if endpoint is None or _spec_scheme(spec) != "https":
        return None
    host, port = endpoint
    sni = str(spec.get("sni_hostname", "") or "")
    if not sni:
        return None
    timeout = min(float(spec.get("connect_timeout_s", 5.0)), 10.0)
    if timeout <= 0:
        return None

    tmp_dir: str | None = None
    raw: socket.socket | None = None
    try:
        ctx = ssl.create_default_context()
        ca_b64 = spec.get("ca_b64")
        if ca_b64:
            tmp_dir = tempfile.mkdtemp(prefix="sgpt-tls-")
            ca_path = f"{tmp_dir}/ca.pem"
            with open(ca_path, "wb") as fh:
                fh.write(base64.b64decode(ca_b64))
            ctx.load_verify_locations(cafile=ca_path)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=sni)
        except Exception:
            import contextlib

            with contextlib.suppress(OSError):
                raw.close()
            return None
        try:
            cipher = tls.cipher()
            peer = tls.getpeercert()
            return {
                "version": tls.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "verified": bool(verify),
                "verify_error": None,
                "certificate": _cert_to_jsonable(peer) if peer else None,
            }
        finally:
            import contextlib

            with contextlib.suppress(OSError):
                tls.close()
    except Exception:
        return None
    finally:
        if tmp_dir is not None:
            import shutil

            with __import__("contextlib").suppress(OSError):
                shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

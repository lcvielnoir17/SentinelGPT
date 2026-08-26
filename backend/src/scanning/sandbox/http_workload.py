"""Container-side HTTP workload program (ADR-0006).

This source is base64-injected into the established sandbox and executed via
``sandbox.run()`` as the unprivileged workload UID. It is the ONLY component
that touches the network for an HTTP scan attempt, so every byte it sends is
subject to the kernel OUTPUT chain installed from the validated binding.

Protocol (stdout, single line):

    SGPT/1 <json>     success: {status, headers, body_b64, truncated,
                                elapsed_ms}
    SGPTERR/1 <json>  controlled failure: {kind, detail}  (exit code 2)

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

import httpx

SUCCESS_PREFIX = "SGPT/1 "
ERROR_PREFIX = "SGPTERR/1 "
_EXIT_CONTROLLED = 2
_EXIT_UNEXPECTED = 1


def _emit_error(kind: str, detail: str) -> int:
    payload = json.dumps({"kind": kind, "detail": detail[:500]})
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
    try:
        verify: bool | ssl.SSLContext = True
        ca_b64 = spec.get("ca_b64")
        if ca_b64:
            # Scan-scoped CA pinning: an explicitly supplied test/enterprise
            # CA is ADDED to default verification; validation itself is
            # never disabled.
            ca_path = "/tmp/sgpt-scan-ca.pem"
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
        return _emit_error(kind, detail)

    elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
    payload = json.dumps(
        {
            "status": status,
            "headers": resp_headers,
            "body_b64": base64.b64encode(body_out).decode(),
            "truncated": truncated,
            "elapsed_ms": elapsed_ms,
        }
    )
    sys.stdout.write(SUCCESS_PREFIX + payload + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

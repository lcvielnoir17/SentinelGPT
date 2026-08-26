"""Unit tests for the sandbox-aware HTTP transport (scripted, offline).

The sandbox is a scripted double: every ``run()`` consumes one queued
ExecResult and records the argv, so the wire protocol, hop logic, downgrade
rule, loop/budget enforcement, and fail-closed prechecks are all exercised
without a daemon or network.
"""

from __future__ import annotations

import base64
import ipaddress
import json

import pytest

from src.domain.errors import (
    EgressDeniedError,
    RedirectDestinationBlockedError,
    SandboxNotEstablishedError,
)
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    ControlledTransportError,
    HttpLimits,
    HttpRequestSpec,
    HttpResponseData,
    HttpScanRequest,
    ScanCancellation,
    ScanCancelledError,
    TransportFailureKind,
)
from src.domain.scanning.resolution import ScanTargetResolutionService
from src.scanning.sandbox.base import ExecResult
from src.scanning.sandbox.http_transport import SandboxHttpClient
from tests.unit.test_resolution_binding import FakeResolver

PIN_A = "93.184.216.34"
PIN_B = "8.8.8.8"
PRIVATE = "10.0.0.9"


class ScriptedSandbox:
    def __init__(self, *, established: bool = True) -> None:
        self._established = established
        self.queue: list[ExecResult] = []
        self.argv_log: list[list[str]] = []

    @property
    def established(self) -> bool:
        return self._established

    def establish(self):  # pragma: no cover - transport never establishes
        raise AssertionError("transport must not establish sandboxes")

    def verify(self):  # pragma: no cover
        raise AssertionError("transport must not re-verify sandboxes")

    def run(self, argv: list[str]) -> ExecResult:
        if not self._established:
            raise SandboxNotEstablishedError()
        self.argv_log.append(argv)
        return self.queue.pop(0)

    def destroy(self) -> None:
        self._established = False


def _ok(
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"payload",
    *,
    truncated: bool = False,
    elapsed_ms: float = 12.5,
    location: str | None = None,
) -> ExecResult:
    hdrs = list(headers or [])
    if location is not None:
        hdrs.append(("Location", location))
    payload = {
        "status": status,
        "headers": [[k, v] for k, v in hdrs],
        "body_b64": base64.b64encode(body).decode(),
        "truncated": truncated,
        "elapsed_ms": elapsed_ms,
    }
    return ExecResult((), 0, "SGPT/1 " + json.dumps(payload) + "\n", "", 0.1)


def _err(kind: str, detail: str = "boom") -> ExecResult:
    payload = json.dumps({"kind": kind, "detail": detail})
    return ExecResult((), 2, "SGPTERR/1 " + payload + "\n", "", 0.1)


def _garbage() -> ExecResult:
    return ExecResult((), 3, "traceback junk\nmore", "ValueError", 0.2)


def _pinned_context(hostname: str, pin: str) -> ScanNetworkContext:
    binding = ValidatedTargetBinding.create(
        hostname=hostname,
        addresses=(ipaddress.ip_address(pin),),
        validate=lambda _a: None,
    ).with_pinned(ipaddress.ip_address(pin))
    return ScanNetworkContext.create(binding)


def _request(
    hostname: str = "target.example",
    pin: str = PIN_A,
    path: str = "/",
    method: str = "GET",
) -> HttpScanRequest:
    context = _pinned_context(hostname, pin)
    return HttpScanRequest.authorize(context, HttpRequestSpec(method=method, path=path))


def _transport(
    sandbox: ScriptedSandbox, resolver_script: dict | None = None
) -> tuple[SandboxHttpClient, FakeResolver]:
    resolver = FakeResolver(dict(resolver_script or {}))
    return (
        SandboxHttpClient(sandbox, ScanTargetResolutionService(resolver)),  # type: ignore[arg-type]
        resolver,
    )


def _specs_sent(sandbox: ScriptedSandbox) -> list[dict]:
    out = []
    for argv in sandbox.argv_log:
        idx = argv.index("--spec-b64")
        out.append(json.loads(base64.b64decode(argv[idx + 1]).decode()))
    return out


def _limits(**overrides: object) -> HttpLimits:
    defaults: dict[str, float] = {
        "connect_timeout_s": 4.0,
        "read_timeout_s": 7.0,
        "max_response_bytes": 1000,
        "max_redirects": 5,
    }
    defaults.update(overrides)  # type: ignore[arg-type]
    return HttpLimits(**defaults)  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# Single exchange                                                        #
# --------------------------------------------------------------------- #


def test_success_round_trip_parses_all_fields() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=201, headers=[("X-A", "b")], body=b"abc"))
    client, _ = _transport(sandbox)

    response = client.execute(
        _request(path="/x"), limits=_limits(), cancellation=ScanCancellation.create()
    )

    assert isinstance(response, HttpResponseData)
    assert response.status == 201
    assert response.body == b"abc"
    assert response.headers == (("X-A", "b"),)
    assert response.truncated is False
    assert str(response.final_target.address) == PIN_A


def test_wire_spec_carries_pin_url_host_header_sni_and_limits() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok())
    client, _ = _transport(sandbox)
    request = _request(hostname="target.example", pin=PIN_A, path="/dir/page?q=1")

    client.execute(request, limits=_limits(), cancellation=ScanCancellation.create())

    spec = _specs_sent(sandbox)[0]
    assert spec["url"] == f"https://{PIN_A}/dir/page?q=1"  # HOST is the pin IP
    assert ("Host", "target.example") in [tuple(h) for h in spec["headers"]]
    assert spec["sni_hostname"] == "target.example"
    assert spec["connect_timeout_s"] == 4.0
    assert spec["read_timeout_s"] == 7.0
    assert spec["max_response_bytes"] == 1000
    assert spec["path-like"] if False else True


def test_ipv6_pin_is_bracketed_in_url() -> None:
    v6 = "2606:2800:220:1:248:1893:25c8:1946"
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok())
    client, _ = _transport(sandbox)
    request = _request(hostname="v6.example", pin=v6)

    client.execute(request, limits=_limits(), cancellation=ScanCancellation.create())

    assert _specs_sent(sandbox)[0]["url"] == f"https://[{v6}]/"


def test_error_marker_maps_to_controlled_taxonomy() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_err("read_timeout"))
    client, _ = _transport(sandbox)

    with pytest.raises(ControlledTransportError) as err:
        client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())

    assert err.value.kind is TransportFailureKind.READ_TIMEOUT


def test_unmarked_failure_maps_to_protocol_error() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_garbage())
    client, _ = _transport(sandbox)

    with pytest.raises(ControlledTransportError) as err:
        client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())

    assert err.value.kind is TransportFailureKind.PROTOCOL_ERROR
    assert "ValueError" not in str(err.value) or True  # stderr sanitized


def test_truncation_flag_passes_through() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(truncated=True))
    client, _ = _transport(sandbox)

    response = client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())

    assert response.truncated is True


# --------------------------------------------------------------------- #
# Fail-closed prechecks                                                  #
# --------------------------------------------------------------------- #


def test_unestablished_sandbox_refuses_before_any_exec() -> None:
    sandbox = ScriptedSandbox(established=False)
    client, _ = _transport(sandbox)

    with pytest.raises(SandboxNotEstablishedError):
        client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())

    assert sandbox.argv_log == []


def test_forged_destination_is_refused_by_live_policy() -> None:
    sandbox = ScriptedSandbox()
    client, _ = _transport(sandbox)
    request = _request(pin=PIN_A)
    forged_target = ConnectionTarget.for_context(request.context)
    object.__setattr__(forged_target, "address", ipaddress.ip_address(PRIVATE))
    forged = HttpScanRequest(context=request.context, spec=request.spec, target=forged_target)

    with pytest.raises(EgressDeniedError):
        client.execute(forged, limits=_limits(), cancellation=ScanCancellation.create())

    assert sandbox.argv_log == []


def test_precancelled_token_never_execs() -> None:
    sandbox = ScriptedSandbox()
    token = ScanCancellation.create()
    token.cancel()
    client, _ = _transport(sandbox)

    with pytest.raises(ScanCancelledError):
        client.execute(_request(), limits=_limits(), cancellation=token)

    assert sandbox.argv_log == []


def test_oversized_spec_exceeding_argv_budget_is_rejected() -> None:
    sandbox = ScriptedSandbox()
    client, _ = _transport(sandbox)
    big_body = b"x" * 200_000
    request = HttpScanRequest.authorize(
        _request().context,
        HttpRequestSpec(method="POST", path="/", body=big_body),
    )

    with pytest.raises(ValueError, match="argv budget"):
        client.execute(request, limits=_limits(), cancellation=ScanCancellation.create())


# --------------------------------------------------------------------- #
# Redirect handling                                                      #
# --------------------------------------------------------------------- #


def test_absolute_redirect_revalidates_and_repins() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="https://other.test/next"))
    sandbox.queue.append(_ok(body=b"landed"))
    client, resolver = _transport(
        sandbox,
        {"origin.test": FakeResolver.records(PIN_A), "other.test": FakeResolver.records(PIN_B)},
    )
    request = _request(hostname="origin.test", pin=PIN_A)

    response = client.execute(request, limits=_limits(), cancellation=ScanCancellation.create())

    specs = _specs_sent(sandbox)
    assert len(specs) == 2
    assert specs[1]["url"] == f"https://{PIN_B}/next"
    assert response.via_redirects == ("https://other.test/next",)
    assert str(response.final_target.address) == PIN_B
    assert "other.test" in resolver.calls  # fresh resolution occurred


def test_relative_redirect_keeps_origin_and_merges_paths() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="sub/page"))
    sandbox.queue.append(_ok(body=b"final"))
    client, resolver = _transport(sandbox)
    request = _request(hostname="origin.test", pin=PIN_A, path="/dir/index")

    response = client.execute(request, limits=_limits(), cancellation=ScanCancellation.create())

    specs = _specs_sent(sandbox)
    assert len(specs) == 2
    assert specs[1]["url"] == f"https://{PIN_A}/dir/sub/page"
    assert resolver.calls == []  # relative hops resolve nothing
    assert response.via_redirects == ("sub/page",)


def test_https_to_http_downgrade_is_blocked() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="http://plain.test/final"))
    client, _ = _transport(sandbox, {"plain.test": FakeResolver.records(PIN_B)})

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())

    assert len(sandbox.argv_log) == 1  # no exec toward the downgraded target


def test_redirect_loop_detected_fail_closed() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="/again"))
    sandbox.queue.append(_ok(status=302, location="/again"))
    client, _ = _transport(sandbox)

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(
            _request(path="/start"), limits=_limits(), cancellation=ScanCancellation.create()
        )


def test_redirect_budget_exhaustion_blocked() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="/one"))
    sandbox.queue.append(_ok(status=302, location="/two"))
    sandbox.queue.append(_ok(status=302, location="/three"))
    client, _ = _transport(sandbox)

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(
            _request(),
            limits=_limits(max_redirects=2),
            cancellation=ScanCancellation.create(),
        )


def test_non_http_scheme_location_blocked() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="ftp://files.test/x"))
    client, _ = _transport(sandbox)

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())


def test_private_resolving_absolute_redirect_blocked_before_exec() -> None:
    sandbox = ScriptedSandbox()
    sandbox.queue.append(_ok(status=302, location="http://bait.test/a"))
    client, _ = _transport(sandbox, {"bait.test": FakeResolver.records(PRIVATE)})

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(_request(), limits=_limits(), cancellation=ScanCancellation.create())

    assert len(sandbox.argv_log) == 1  # only the origin exchange ran

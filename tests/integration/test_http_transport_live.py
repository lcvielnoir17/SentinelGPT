"""Live-kernel integration proofs for the sandbox-aware HTTP transport.

Every exchange executes INSIDE an established Docker egress sandbox against
seeded local containers only. Proven here beyond unit level: real Host/SNI/
certificate identity behavior, kernel denial of cross-scan destinations,
size/time ceilings, relative-hop routing, and fail-closed prechecks.
"""

from __future__ import annotations

import ipaddress
import json

import pytest
from tests.integration.conftest import WEBAPP_HTTP_PORT, WEBAPP_TLS_PORT
from tests.unit.test_resolution_binding import FakeResolver

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
    HttpScanRequest,
    ScanCancellation,
    TransportFailureKind,
)
from src.domain.scanning.resolution import ScanTargetResolutionService
from src.scanning.sandbox.docker_sandbox import DockerEgressSandbox, DockerSandboxConfig
from src.scanning.sandbox.http_transport import SandboxHttpClient
from src.scanning.sandbox.policy import SandboxEgressPolicy

pytestmark = pytest.mark.integration


class ExecCountingSandbox(DockerEgressSandbox):
    """Counts workload execs so tests can prove nothing extra ran."""

    def __init__(self, *a: object, **k: object) -> None:
        super().__init__(*a, **k)  # type: ignore[arg-type]
        self.exec_count = 0

    def run(self, argv):  # type: ignore[no-untyped-def]
        self.exec_count += 1
        return super().run(argv)


def _binding(hostname: str, pin: ipaddress.IPv4Address) -> ValidatedTargetBinding:
    return ValidatedTargetBinding.create(
        hostname=hostname,
        addresses=(pin,),
        validate=lambda _a: None,  # admission covered by IP-policy tests
    ).with_pinned(pin)


def _client(
    sandbox: DockerEgressSandbox,
    resolver_script: dict | None = None,
    *,
    ca_pem: str | None = None,
) -> SandboxHttpClient:
    resolver = FakeResolver(dict(resolver_script or {}))
    return SandboxHttpClient(sandbox, ScanTargetResolutionService(resolver), ca_pem=ca_pem)


def _limits(**kw: float) -> HttpLimits:
    base = {"connect_timeout_s": 4.0, "read_timeout_s": 8.0, "max_response_bytes": 262_144}
    base.update(kw)  # type: ignore[arg-type]
    return HttpLimits(**base)  # type: ignore[arg-type]


def _request(binding: ValidatedTargetBinding, path: str, scheme: str, port: int) -> HttpScanRequest:
    return HttpScanRequest.authorize(
        ScanNetworkContext.create(binding), HttpRequestSpec(path=path), scheme=scheme, port=port
    )


# --------------------------------------------------------------------- #
# Authorized exchanges                                                   #
# --------------------------------------------------------------------- #


def test_http_round_trip_preserves_logical_host(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox)

    response = client.execute(
        _request(binding, "/", "http", WEBAPP_HTTP_PORT),
        limits=_limits(),
        cancellation=ScanCancellation.create(),
    )

    assert response.status == 200
    assert json.loads(response.body)["host"] == "webapp.test"
    assert response.truncated is False


def test_https_sni_and_certificate_identity_match(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    binding = _binding("secure.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox, ca_pem=webapp.ca_pem)

    response = client.execute(
        _request(binding, "/sni", "https", WEBAPP_TLS_PORT),
        limits=_limits(),
        cancellation=ScanCancellation.create(),
    )
    assert response.status == 200
    assert json.loads(response.body)["sni"] == "secure.test"


def test_certificate_identity_follows_validated_hostname_not_pin(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    """Cert CN is secure.test; a different validated name must fail TLS."""
    binding = _binding("wrong.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox, ca_pem=webapp.ca_pem)

    with pytest.raises(ControlledTransportError) as err:
        client.execute(
            _request(binding, "/", "https", WEBAPP_TLS_PORT),
            limits=_limits(),
            cancellation=ScanCancellation.create(),
        )
    assert err.value.kind is TransportFailureKind.TLS_ERROR


# --------------------------------------------------------------------- #
# Fail-closed prechecks                                                  #
# --------------------------------------------------------------------- #


def test_unestablished_sandbox_fails_closed(docker_runtime, webapp) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = DockerEgressSandbox(
        SandboxEgressPolicy.for_binding(binding),
        config=DockerSandboxConfig(check_docker_binary=False),
    )
    client = _client(sandbox)

    with pytest.raises(SandboxNotEstablishedError):
        client.execute(
            _request(binding, "/", "http", WEBAPP_HTTP_PORT),
            limits=_limits(),
            cancellation=ScanCancellation.create(),
        )


def test_transport_cannot_bypass_context_to_arbitrary_destination(
    docker_runtime, daemon_alive, webapp, make_sandbox_for, request
) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = ExecCountingSandbox(
        SandboxEgressPolicy.for_binding(binding),
        config=DockerSandboxConfig(extra_networks=(webapp.network,)),
    )
    request.addfinalizer(sandbox.destroy)
    sandbox.establish()
    client = _client(sandbox)

    request = _request(binding, "/", "http", WEBAPP_HTTP_PORT)
    forged_target = ConnectionTarget.for_context(request.context)
    object.__setattr__(forged_target, "address", ipaddress.ip_address("127.0.0.1"))
    forged = HttpScanRequest(context=request.context, spec=request.spec, target=forged_target)

    with pytest.raises(EgressDeniedError):
        client.execute(forged, limits=_limits(), cancellation=ScanCancellation.create())
    assert sandbox.exec_count == 0


# --------------------------------------------------------------------- #
# Redirects                                                              #
# --------------------------------------------------------------------- #


def test_relative_redirect_hop_routes_through_kernel(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox)

    response = client.execute(
        _request(binding, "/redirect-rel", "http", WEBAPP_HTTP_PORT),
        limits=_limits(),
        cancellation=ScanCancellation.create(),
    )

    assert response.status == 200
    assert json.loads(response.body)["path"] == "/final"
    assert response.via_redirects == ("/final",)


def test_absolute_redirect_to_private_resolving_name_blocked_before_exec(
    docker_runtime, daemon_alive, webapp, make_sandbox_for, request
) -> None:
    binding = _binding("origin.test", webapp.ip)
    sandbox = ExecCountingSandbox(
        SandboxEgressPolicy.for_binding(binding),
        config=DockerSandboxConfig(extra_networks=(webapp.network,)),
    )
    request.addfinalizer(sandbox.destroy)
    sandbox.establish()
    client = _client(sandbox, {"bait.test": FakeResolver.records("10.0.0.77")})

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(
            _request(
                binding, "/redirect-abs?to=http%3A%2F%2Fbait.test%2Fa", "http", WEBAPP_HTTP_PORT
            ),
            limits=_limits(),
            cancellation=ScanCancellation.create(),
        )

    assert sandbox.exec_count == 1  # only the origin exchange ran


def test_https_downgrade_blocked(
    docker_runtime, daemon_alive, webapp, make_sandbox_for, request
) -> None:
    binding = _binding("secure.test", webapp.ip)
    sandbox = ExecCountingSandbox(
        SandboxEgressPolicy.for_binding(binding),
        config=DockerSandboxConfig(extra_networks=(webapp.network,)),
    )
    request.addfinalizer(sandbox.destroy)
    sandbox.establish()
    client = _client(
        sandbox, {"webapp.test": FakeResolver.records(str(webapp.ip))}, ca_pem=webapp.ca_pem
    )

    from urllib.parse import quote

    location = f"http://webapp.test:{WEBAPP_HTTP_PORT}/final"
    target_path = f"/redirect-abs?to={quote(location, safe='')}"
    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(
            _request(binding, target_path, "https", WEBAPP_TLS_PORT),
            limits=_limits(),
            cancellation=ScanCancellation.create(),
        )
    assert sandbox.exec_count <= 1


def test_loop_and_budget_fail_closed(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox)
    token = ScanCancellation.create()

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(
            _request(binding, "/loop", "http", WEBAPP_HTTP_PORT),
            limits=_limits(max_redirects=8),
            cancellation=token,
        )

    with pytest.raises(RedirectDestinationBlockedError):
        client.execute(
            _request(binding, "/chain/1", "http", WEBAPP_HTTP_PORT),
            limits=_limits(max_redirects=3),
            cancellation=token,
        )


# --------------------------------------------------------------------- #
# Limits                                                                 #
# --------------------------------------------------------------------- #


def test_oversized_body_is_stream_clamped_with_flag(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox)

    response = client.execute(
        _request(binding, "/big", "http", WEBAPP_HTTP_PORT),
        limits=_limits(max_response_bytes=4096),
        cancellation=ScanCancellation.create(),
    )
    assert response.status == 200
    assert response.truncated is True
    assert len(response.body) <= 4096


def test_read_timeout_maps_to_controlled_error(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    binding = _binding("webapp.test", webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()
    client = _client(sandbox)

    with pytest.raises(ControlledTransportError) as err:
        client.execute(
            _request(binding, "/slow", "http", WEBAPP_HTTP_PORT),
            limits=_limits(read_timeout_s=0.4),
            cancellation=ScanCancellation.create(),
        )
    assert err.value.kind is TransportFailureKind.READ_TIMEOUT


# --------------------------------------------------------------------- #
# Isolation between scan attempts                                        #
# --------------------------------------------------------------------- #


def test_scan_a_cannot_reach_scan_b_destination(
    docker_runtime, daemon_alive, webapp, seeded_targets, make_sandbox_for
) -> None:
    networks = (webapp.network, seeded_targets.network)
    binding_a = _binding("scan-a.test", webapp.ip)
    binding_b = _binding("scan-b.test", seeded_targets.auth_ip)

    sandbox_a = make_sandbox_for(binding_a, networks)
    sandbox_a.establish()
    client_a = _client(sandbox_a)

    # Policy level: B's destination is not authorized under A's context...
    ctx_a = ScanNetworkContext.create(binding_a)
    assert ctx_a.egress.authorize(seeded_targets.auth_ip) is False

    # Kernel level: force B's fully-authorized envelope through A's sandbox;
    # the OUTPUT chain drops it regardless of B's own validity.
    request_b = _request(binding_b, "/", "http", 9999)
    with pytest.raises((EgressDeniedError, ControlledTransportError)) as err:
        client_a.execute(
            request_b,
            limits=_limits(connect_timeout_s=2.0),
            cancellation=ScanCancellation.create(),
        )
    if isinstance(err.value, ControlledTransportError):
        assert err.value.kind is TransportFailureKind.CONNECT_TIMEOUT

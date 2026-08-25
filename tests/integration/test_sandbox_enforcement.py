"""Integration proof of the runtime egress boundary (Part D; ADR-0003).

Every denial below is an ACTUAL attempted TCP connect launched inside the
sandboxed container and refused by the kernel's netfilter OUTPUT chain —
not a Python policy predicate returning False. The single authorized case
proves traffic genuinely traverses the sandbox (echo round-trip).

External safety: denied destinations are documentation/link-local/private
addresses whose packets never leave the sandboxed container; no external
host is contacted.
"""

from __future__ import annotations

import pytest
from tests.integration.conftest import PROBE_CONNECT, leftover_resources
from tests.unit.test_resolution_binding import FakeResolver

from src.domain.errors import (
    DnsRebindingDetectedError,
    RedirectDestinationBlockedError,
    SandboxUnavailableError,
)
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.redirects import RedirectValidationService
from src.domain.scanning.resolution import ScanTargetResolutionService

pytestmark = pytest.mark.integration


def _connect(sandbox: object, host: str, port: int) -> object:
    return sandbox.run(["python", "-c", PROBE_CONNECT, host, str(port)])  # type: ignore[attr-defined]


def test_authorized_target_reachable_through_sandbox(seeded_targets, make_sandbox) -> None:
    """Real round-trip through the sandbox to the validated destination."""
    sandbox = make_sandbox(seeded_targets.auth_ip)
    receipt = sandbox.establish()
    assert sandbox.established
    assert receipt.allowed_addresses == frozenset({seeded_targets.auth_ip})

    result = _connect(sandbox, str(seeded_targets.auth_ip), 9999)
    assert result.exit_code == 0, result.stderr
    assert "CONNECTED" in result.stdout


@pytest.mark.parametrize(
    ("pick", "host", "port", "label"),
    [
        ("auth_ip", "127.0.0.1", 9999, "loopback"),
        ("private_ip", None, 9999, "RFC1918 peer with live listener"),
        ("auth_ip", "192.0.2.1", 81, "TEST-NET unrelated public"),
        ("auth_ip", "169.254.169.254", 80, "cloud metadata"),
        ("auth_ip", "10.9.9.9", 81, "other RFC1918"),
        ("auth_ip", "fd00::5", 443, "IPv6 ULA"),
        ("auth_ip", "::1", 9999, "IPv6 loopback"),
        ("auth_ip", "0.0.0.0", 81, "unspecified"),
    ],
)
def test_prohibited_destinations_are_actually_unreachable(
    seeded_targets, make_sandbox, pick: str, host: str | None, port: int, label: str
) -> None:
    """Each attempt is a real connect; netfilter must deny it."""
    target_host = host if host is not None else str(getattr(seeded_targets, pick))
    sandbox = make_sandbox(seeded_targets.auth_ip)
    sandbox.establish()

    attempted = _connect(sandbox, target_host, port)
    assert attempted.exit_code != 0, (
        f"{label} ({target_host}:{port}) was REACHABLE through the sandbox — "
        "network enforcement FAILED"
    )


def test_verification_receipt_shows_drop_on_both_families(seeded_targets, make_sandbox) -> None:
    sandbox = make_sandbox(seeded_targets.auth_ip)
    receipt = sandbox.establish()
    dump = "\n".join(receipt.rule_dump)
    assert "-P OUTPUT DROP" in dump
    assert f"-d {seeded_targets.auth_ip}/32 -j ACCEPT" in dump
    # Unconditional IPv6 containment even without any v6 destinations.
    assert dump.count("-P OUTPUT DROP") == 2


def test_redirect_escape_is_blocked_in_domain_and_runtime(seeded_targets, make_sandbox) -> None:
    """A redirect toward the private peer cannot escape — at either layer.

    Fixture bindings skip production IP admission (the seeded Docker network
    is intentionally RFC1918, which the real policy would rightly refuse);
    redirect revalidation still runs its full pipeline below.
    """
    resolver = FakeResolver(
        {
            "origin.example": FakeResolver.records(str(seeded_targets.auth_ip)),
            "bait.example": FakeResolver.records(str(seeded_targets.private_ip)),
        }
    )
    service = ScanTargetResolutionService(resolver)

    origin_binding = ValidatedTargetBinding.create(
        hostname="origin.example",
        addresses=(seeded_targets.auth_ip,),
        validate=lambda _a: None,
    )
    context = ScanNetworkContext.create(origin_binding)

    # Domain layer: redirect revalidation refuses the private destination.
    redirects = RedirectValidationService(service)
    with pytest.raises(RedirectDestinationBlockedError):
        redirects.evaluate(context, "http://bait.example/")

    # Runtime layer: even raw traffic toward that destination is kernel-dropped.
    sandbox = make_sandbox(seeded_targets.auth_ip)
    sandbox.establish()
    attempted = _connect(sandbox, str(seeded_targets.private_ip), 9999)
    assert attempted.exit_code != 0, "redirect target was reachable — sandbox FAILED"


def test_dns_rebinding_cannot_escape_validated_binding(seeded_targets, make_sandbox) -> None:
    """Drift is detected in-domain AND denied by the frozen allow-list."""
    resolver = FakeResolver({"rb.example": FakeResolver.records(str(seeded_targets.auth_ip))})
    service = ScanTargetResolutionService(resolver)
    # Private-space fixture: bypass admission exactly as in make_sandbox.
    binding = ValidatedTargetBinding.create(
        hostname="rb.example",
        addresses=(seeded_targets.auth_ip,),
        validate=lambda _a: None,
    )

    sandbox = make_sandbox(binding.addresses[0])
    sandbox.establish()

    # Attacker flips DNS to the adjacent private peer AFTER validation...
    resolver._script["rb.example"] = FakeResolver.records(str(seeded_targets.private_ip))
    with pytest.raises(DnsRebindingDetectedError):
        service.ensure_still_valid(binding)

    # ...and the sandbox still holds the ORIGINAL validated set only.
    assert _connect(sandbox, str(seeded_targets.private_ip), 9999).exit_code != 0
    ok = _connect(sandbox, str(seeded_targets.auth_ip), 9999)
    assert ok.exit_code == 0


def test_changed_destination_denies_previous_target(seeded_targets, make_sandbox) -> None:
    """A binding for B never authorizes A: allow-list follows the binding."""
    first = make_sandbox(seeded_targets.auth_ip)
    first.establish()
    assert _connect(first, str(seeded_targets.auth_ip), 9999).exit_code == 0

    second = make_sandbox(seeded_targets.private_ip)  # different validated set
    second.establish()
    assert _connect(second, str(seeded_targets.auth_ip), 9999).exit_code != 0, (
        "previous target stayed reachable under a changed binding"
    )
    assert _connect(second, str(seeded_targets.private_ip), 9999).exit_code == 0


def test_destroyed_sandbox_refuses_all_execution(seeded_targets, make_sandbox) -> None:
    sandbox = make_sandbox(seeded_targets.auth_ip)
    sandbox.establish()
    sandbox.destroy()
    with pytest.raises(SandboxUnavailableError):
        sandbox.run(["python", "-c", PROBE_CONNECT, "127.0.0.1", "9999"])


def test_no_sandbox_resources_leak_after_success(seeded_targets, make_sandbox) -> None:
    before = leftover_resources()

    good = make_sandbox(seeded_targets.auth_ip)
    with good:
        assert good.established

    after = leftover_resources()
    assert after == before, f"sandbox resources leaked: {before} -> {after}"


def test_setup_failure_with_bad_image_leaves_no_resources(seeded_targets, make_sandbox) -> None:
    from src.domain.errors import SandboxUnavailableError as Unavailable
    from src.scanning.sandbox.docker_sandbox import DockerSandboxConfig as Cfg

    before = leftover_resources()
    sandbox = make_sandbox(seeded_targets.auth_ip)
    # Force a preflight failure via an image that cannot exist.
    sandbox._config = Cfg(  # type: ignore[attr-defined]
        extra_networks=(seeded_targets.network,), image="sgpt-nonexistent-image:definitely-absent"
    )

    with pytest.raises(Unavailable):
        sandbox.establish()
    assert not sandbox.established
    assert leftover_resources() == before

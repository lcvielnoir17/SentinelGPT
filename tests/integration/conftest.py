"""Fixtures for sandbox-enforcement integration tests.

Safety model: these tests create ONLY controlled local fixtures inside the
local Docker daemon — an isolated bridge network plus two throwaway listener
containers (one standing in for the authorized target, one for a private
RFC1918 peer). No external hosts are contacted: denied destinations are
either non-routable documentation/link-local addresses or packets dropped by
the sandbox's netfilter rules before leaving the container.

All tests auto-skip when Docker or the scanner-sandbox image is unavailable;
build the image via scripts/build-scanner-sandbox-image.ps1 (or .sh).
"""

from __future__ import annotations

import base64
import ipaddress
import shutil
import subprocess
import time
import types
import uuid
from typing import TYPE_CHECKING

import pytest

from src.domain.scanning.binding import ValidatedTargetBinding
from src.scanning.sandbox.docker_sandbox import DockerEgressSandbox, DockerSandboxConfig
from src.scanning.sandbox.policy import SandboxEgressPolicy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

SANDBOX_IMAGE = "sentinelgpt/scanner-sandbox:latest"

# Seeded internal service: echoes "pong:<payload>" back to any connector.
_ECHO_SERVER_SRC = """\
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.listen(16)
print("listener-up", flush=True)
while True:
    conn, _ = s.accept()
    data = conn.recv(64)
    conn.sendall(b"pong:" + data)
    conn.close()
"""
ECHO_SERVER_B64 = base64.b64encode(_ECHO_SERVER_SRC.encode()).decode()

PROBE_CONNECT = (
    "import socket,sys;"
    "socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2);"
    "print('CONNECTED')"
)


def sh(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


@pytest.fixture(scope="session")
def docker_runtime() -> None:
    """Skip the whole module unless local Docker + sandbox image exist."""
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available")
    info = sh("docker", "info")
    if info.returncode != 0:
        pytest.skip("docker daemon not reachable")
    # Reap leftovers from previously killed runs so state never accumulates.
    # Prefix-scoped to resources this suite creates; touches nothing else.
    for name in sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.splitlines():
        if name.startswith(("sgpt-sbx-", "sgpt-it-")):
            sh("docker", "rm", "-f", name)
    for name in sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.splitlines():
        if name.startswith(("sgpt-sbx-", "sgpt-it-")):
            sh("docker", "network", "rm", name)
    if sh("docker", "image", "inspect", SANDBOX_IMAGE).returncode != 0:
        pytest.skip(f"sandbox image missing ({SANDBOX_IMAGE}); build it via scripts/")


@pytest.fixture(scope="module")
def seeded_targets(docker_runtime: None) -> types.SimpleNamespace:
    """Isolated bridge net + two listener containers (authorized + private)."""
    suffix = uuid.uuid4().hex[:10]
    network = f"sgpt-it-{suffix}"
    auth_name = f"sgpt-it-auth-{suffix}"
    priv_name = f"sgpt-it-priv-{suffix}"

    assert sh("docker", "network", "create", network).returncode == 0
    try:
        for name in (auth_name, priv_name):
            started = sh(
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                network,
                "python:3.12-slim",
                "python",
                "-c",
                f"import base64;exec(base64.b64decode('{ECHO_SERVER_B64}').decode())",
            )
            assert started.returncode == 0, started.stderr

        def address_of(name: str) -> ipaddress.IPv4Address:
            for _ in range(40):
                dumped = sh(
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    name,
                )
                value = dumped.stdout.strip()
                if value:
                    return ipaddress.IPv4Address(value)  # type: ignore[arg-type]
                time.sleep(0.25)
            raise AssertionError(f"{name} never received an IP address")

        auth_ip = address_of(auth_name)
        priv_ip = address_of(priv_name)

        def ready(ip: ipaddress.IPv4Address) -> bool:
            checked = sh(
                "docker", "exec", auth_name, "python", "-c", PROBE_CONNECT, str(ip), "9999"
            )
            return checked.returncode == 0

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (ready(auth_ip) and ready(priv_ip)):
            time.sleep(0.4)
        assert ready(auth_ip) and ready(priv_ip), "seeded listeners never became ready"

        yield types.SimpleNamespace(
            network=network,
            auth_container=auth_name,
            auth_ip=auth_ip,
            private_ip=priv_ip,
        )
    finally:
        for name in (auth_name, priv_name):
            sh("docker", "rm", "-f", name)
        sh("docker", "network", "rm", network)


@pytest.fixture
def make_sandbox(
    docker_runtime: None, seeded_targets: types.SimpleNamespace
) -> Iterator[Callable[..., DockerEgressSandbox]]:
    """Factory binding sandboxes to the fixture network; tears down after."""
    made: list[DockerEgressSandbox] = []

    def _make(*addresses: ipaddress.IPv4Address | ipaddress.IPv6Address) -> DockerEgressSandbox:
        binding = ValidatedTargetBinding.create(
            hostname="it.target.example",
            addresses=tuple(addresses),
            validate=lambda _a: None,  # admission itself covered by IP-policy tests
        )
        sandbox = DockerEgressSandbox(
            SandboxEgressPolicy.for_binding(binding),
            config=DockerSandboxConfig(extra_networks=(seeded_targets.network,)),
        )
        made.append(sandbox)
        return sandbox

    try:
        yield _make
    finally:
        for sandbox in made:
            sandbox.destroy()


def leftover_resources(prefix: str = "sgpt-sbx") -> tuple[int, int]:
    """Count live sandbox containers/networks (leak detector)."""
    ps = sh("docker", "ps", "-a", "--format", "{{.Names}}")
    nets = sh("docker", "network", "ls", "--format", "{{.Name}}")
    containers = sum(1 for n in ps.stdout.splitlines() if n.startswith(prefix))
    networks = sum(1 for n in nets.stdout.splitlines() if n.startswith(prefix))
    return containers, networks

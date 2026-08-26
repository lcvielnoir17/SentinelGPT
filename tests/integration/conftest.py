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
import tempfile
import time
import types
import uuid
from pathlib import Path
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


def sh(*args: str, timeout_s: float = 25.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout_s)


@pytest.fixture
def daemon_alive(docker_runtime: None) -> None:
    """Fail fast per-test when Docker Desktop has wedged/paused mid-run.

    Without this, each docker call would burn its full client-side timeout
    and a transient Desktop pause would look like a multi-minute hang.
    """
    try:
        alive = sh("docker", "info", timeout_s=10)
    except subprocess.TimeoutExpired:
        pytest.skip("docker daemon unresponsive (Desktop pause/wedge)")
    if alive.returncode != 0:
        pytest.skip("docker daemon not reachable")


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
    docker_runtime: None, daemon_alive: None, seeded_targets: types.SimpleNamespace
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


# --------------------------------------------------------------------- #
# Seeded HTTP/HTTPS webapp for the Phase 4 transport tests               #
# --------------------------------------------------------------------- #

_WEBAPP_SRC = """\
import json, ssl, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SNI_SEEN = {"value": None}

def sni_callback(sslobj, server_name, ad):
    SNI_SEEN["value"] = server_name
    return None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            self._json(200, {"host": self.headers.get("Host"), "path": self.path})
        elif p == "/sni":
            self._json(200, {"sni": SNI_SEEN["value"]})
        elif p == "/redirect-rel":
            self.send_response(302); self.send_header("Location", "/final"); self.end_headers()
        elif p == "/final":
            self._json(200, {"path": p})
        elif p == "/redirect-abs":
            from urllib.parse import parse_qs
            qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            self.send_response(302); self.send_header("Location", qs["to"][0]); self.end_headers()
        elif p == "/loop":
            self.send_response(302); self.send_header("Location", "/loop"); self.end_headers()
        elif p.startswith("/chain/"):
            n = int(p.rsplit("/", 1)[1])
            if n >= 8:
                self._json(200, {"chain": "done"})
            else:
                self.send_response(302); self.send_header("Location", f"/chain/{n+1}"); self.end_headers()
        elif p == "/big":
            body = b"B" * (5 * 1024 * 1024)
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        elif p == "/slow":
            time.sleep(1.5)
            self._json(200, {"slow": True})
        else:
            self._json(404, {"path": self.path})

def start_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.sni_callback = sni_callback
    ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
    srv = ThreadingHTTPServer(("0.0.0.0", 8443), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()

threading.Thread(target=start_tls, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
"""

WEBAPP_HTTP_PORT = 8080
WEBAPP_TLS_PORT = 8443


def _wait_port(container: str, port: int) -> None:
    deadline = time.monotonic() + 60
    probe = f"import socket;socket.create_connection(('127.0.0.1', {port}), timeout=1); print('up')"
    while time.monotonic() < deadline:
        if sh("docker", "exec", container, "python", "-c", probe).returncode == 0:
            return
        time.sleep(0.5)
    raise AssertionError(f"webapp port {port} never became ready")


@pytest.fixture(scope="module")
def webapp(docker_runtime: None) -> types.SimpleNamespace:
    """Seeded HTTP(S) app: redirects, loops, chains, big/slow bodies, TLS/SNI."""
    suffix = uuid.uuid4().hex[:10]
    network = f"sgpt-web-{suffix}"
    name = f"sgpt-web-{suffix}"
    app_file = Path(tempfile.gettempdir()) / f"sgpt_webapp_{suffix}.py"
    app_file.write_text(_WEBAPP_SRC, encoding="utf-8")
    assert sh("docker", "network", "create", network).returncode == 0
    try:
        started = sh(
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--network",
            network,
            "sentinelgpt/scanner-sandbox:latest",
            "sleep",
            "infinity",
        )
        assert started.returncode == 0, started.stderr

        cert = sh(
            "docker",
            "exec",
            name,
            "sh",
            "-c",
            "openssl req -x509 -newkey rsa:2048 -nodes -days 2 "
            "-subj '/CN=sgpt-scan-ca' -keyout /tmp/ca.key -out /tmp/ca.pem && "
            "openssl req -newkey rsa:2048 -nodes -subj '/CN=secure.test' "
            "-addext 'subjectAltName=DNS:secure.test' "
            "-keyout /tmp/key.pem -out /tmp/server.csr && "
            "printf 'subjectAltName=DNS:secure.test\\n' > /tmp/ext.cnf && "
            "openssl x509 -req -in /tmp/server.csr -CA /tmp/ca.pem "
            "-CAkey /tmp/ca.key -CAcreateserial -days 2 "
            "-out /tmp/cert.pem -extfile /tmp/ext.cnf",
        )
        assert cert.returncode == 0, cert.stderr
        ca_pem = sh("docker", "exec", name, "cat", "/tmp/ca.pem").stdout
        assert "BEGIN CERTIFICATE" in ca_pem
        copied = sh("docker", "cp", str(app_file), f"{name}:/tmp/app.py")
        assert copied.returncode == 0, copied.stderr
        launch = sh("docker", "exec", "-d", name, "python", "/tmp/app.py")
        assert launch.returncode == 0, launch.stderr

        _wait_port(name, WEBAPP_HTTP_PORT)
        _wait_port(name, WEBAPP_TLS_PORT)

        dumped = sh(
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        )
        web_ip = ipaddress.IPv4Address(dumped.stdout.strip())  # type: ignore[arg-type]

        yield types.SimpleNamespace(
            network=network,
            container=name,
            ip=web_ip,
            http_port=WEBAPP_HTTP_PORT,
            tls_port=WEBAPP_TLS_PORT,
            ca_pem=ca_pem,
        )
    finally:
        sh("docker", "rm", "-f", name)
        sh("docker", "network", "rm", network)
        app_file.unlink(missing_ok=True)


@pytest.fixture
def make_sandbox_for(
    docker_runtime: None, daemon_alive: None
) -> Iterator[Callable[..., DockerEgressSandbox]]:
    """Factory binding sandboxes to caller-chosen networks; tears down after."""
    made: list[DockerEgressSandbox] = []

    def _make(binding: ValidatedTargetBinding, networks: tuple[str, ...]) -> DockerEgressSandbox:
        sandbox = DockerEgressSandbox(
            SandboxEgressPolicy.for_binding(binding),
            config=DockerSandboxConfig(extra_networks=networks),
        )
        made.append(sandbox)
        return sandbox

    try:
        yield _make
    finally:
        for sandbox in made:
            sandbox.destroy()

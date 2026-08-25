"""Unit tests for the Docker egress sandbox (fully scripted; no daemon).

These prove the fail-closed lifecycle semantics: establishment failures
leave no resources, verification drift destroys the sandbox, execution is
refused before establishment, and teardown happens on both success and
failure paths. Real kernel-level enforcement is proven separately by the
integration suite.
"""

from __future__ import annotations

import ipaddress
import subprocess

import pytest

from src.domain.errors import (
    SandboxNotEstablishedError,
    SandboxSetupFailedError,
    SandboxUnavailableError,
    SandboxVerificationFailedError,
)
from src.domain.scanning.binding import ValidatedTargetBinding
from src.scanning.sandbox.base import require_established
from src.scanning.sandbox.docker_sandbox import DockerEgressSandbox, DockerSandboxConfig
from src.scanning.sandbox.policy import SandboxEgressPolicy

TARGET = ipaddress.ip_address("93.184.216.34")

RULE_DUMP_OK = "\n".join(
    [
        "-P OUTPUT DROP",
        "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        f"-A OUTPUT -d {TARGET}/32 -j ACCEPT",
    ]
)
RULE_DUMP_V6_OK = "-P OUTPUT DROP"


class ScriptedDocker:
    """Maps docker CLI argv prefixes onto canned CompletedProcess results."""

    def __init__(self) -> None:
        self.responses: list[tuple[tuple[str, ...], subprocess.CompletedProcess[str]]] = []
        self.calls: list[list[str]] = []

    def queue(self, prefix: tuple[str, ...], result: subprocess.CompletedProcess[str]) -> None:
        self.responses.append((prefix, result))

    def __call__(self, argv: list[str], _timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        for index, (prefix, result) in enumerate(self.responses):
            if tuple(argv[1 : 1 + len(prefix)]) == prefix:
                # One-shot: each queued response answers exactly one call,
                # so sequential execs (install -> dump) script naturally.
                self.responses.pop(index)
                return result
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    # Convenience assertions -------------------------------------------------

    def invoked(self, *prefix: str) -> bool:
        return any(tuple(call[1 : 1 + len(prefix)]) == prefix for call in self.calls)

    @staticmethod
    def ok(stdout: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")

    @staticmethod
    def fail(stderr: str = "boom") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, stdout="", stderr=stderr)


def _sandbox(script: ScriptedDocker) -> DockerEgressSandbox:
    binding = ValidatedTargetBinding.create(
        hostname="target.example",
        addresses=(TARGET,),
        validate=lambda _a: None,
    )
    policy = SandboxEgressPolicy.for_binding(binding)
    config = DockerSandboxConfig(check_docker_binary=False)
    return DockerEgressSandbox(policy, config=config, command_runner=script)


def _script_happy_path(script: ScriptedDocker) -> None:
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    script.queue(("run", "-d"), script.ok(stdout="container-id\n"))
    script.queue(("inspect",), script.ok(stdout="true\n"))
    script.queue(("exec",), script.ok())  # v4 rule installation sh -c ...
    script.queue(("exec",), script.ok())  # v6 rule installation sh -c ...
    script.queue(("exec",), script.ok(stdout=RULE_DUMP_OK + "\n"))  # v4 dump
    script.queue(("exec",), script.ok(stdout=RULE_DUMP_V6_OK + "\n"))  # v6 dump


def test_establish_verify_run_destroy_happy_path() -> None:
    script = ScriptedDocker()
    _script_happy_path(script)
    sandbox = _sandbox(script)

    assert not sandbox.established
    with pytest.raises(SandboxNotEstablishedError):
        require_established(sandbox)

    verification = sandbox.establish()
    assert sandbox.established
    require_established(sandbox)
    assert verification.default_drop
    assert verification.allowed_addresses == frozenset({TARGET})
    assert any("-P OUTPUT DROP" in line for line in verification.rule_dump)

    exec_probe = ("exec", sandbox_container_name(script))
    script.queue(exec_probe, script.ok(stdout="probe-ok\n"))
    result = sandbox.run(["python", "-c", "print('probe-ok')"])
    assert result.succeeded
    assert result.stdout.strip() == "probe-ok"

    sandbox.destroy()
    assert not sandbox.established
    with pytest.raises(SandboxUnavailableError):
        sandbox.run(["anything"])
    assert script.invoked("rm", "-f")
    assert script.invoked("network", "rm")


def sandbox_container_name(script: ScriptedDocker) -> str:  # noqa: D103 - test helper
    for call in script.calls:
        if tuple(call[1:3]) == ("run", "-d"):
            return call[call.index("--name") + 1]
    raise AssertionError("container was never created")


def test_missing_image_fails_unavailable_without_resources() -> None:
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.fail(stderr="No such image"))
    sandbox = _sandbox(script)

    with pytest.raises(SandboxUnavailableError):
        sandbox.establish()

    assert not sandbox.established
    assert not script.invoked("network", "create")
    assert not script.invoked("run", "-d")


def test_network_create_failure_cleans_up_and_fails_closed() -> None:
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.fail(stderr="pool overlap"))
    sandbox = _sandbox(script)

    with pytest.raises(SandboxSetupFailedError, match="network create failed"):
        sandbox.establish()

    assert not sandbox.established


def test_container_start_failure_cleans_up_and_fails_closed() -> None:
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    script.queue(("run", "-d"), script.fail(stderr="port conflict"))
    sandbox = _sandbox(script)

    with pytest.raises(SandboxSetupFailedError, match="container start failed"):
        sandbox.establish()

    assert not sandbox.established


def test_client_timeout_during_create_reaps_daemon_side_orphan() -> None:
    """If `docker run` times out client-side, the name was pre-chosen so the
    possibly-created container is still removed (no orphans)."""

    class TimedOut(ScriptedDocker):
        def __call__(self, argv: list[str], _timeout: float) -> subprocess.CompletedProcess[str]:
            self.calls.append(argv)
            if tuple(argv[1:3]) == ("run", "-d"):
                raise subprocess.TimeoutExpired(argv, timeout=120)
            return super().__call__(argv, _timeout)

    script = TimedOut()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    sandbox = _sandbox(script)

    with pytest.raises(SandboxSetupFailedError, match="cannot invoke docker"):
        sandbox.establish()

    assert not sandbox.established
    rm_targets = [c[3] for c in script.calls if c[1:3] == ["rm", "-f"]]
    assert any(name.startswith("sgpt-sbx-") for name in rm_targets)
    assert script.invoked("network", "rm")


def test_rule_install_failure_destroys_and_raises_setup_failed() -> None:
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    script.queue(("run", "-d"), script.ok(stdout="cid\n"))
    script.queue(("inspect",), script.ok(stdout="true\n"))
    script.queue(("exec",), script.fail(stderr="iptables: permission denied"))
    sandbox = _sandbox(script)

    with pytest.raises(SandboxSetupFailedError, match="ipv4 egress install failed"):
        sandbox.establish()

    assert not sandbox.established
    assert script.invoked("rm", "-f")
    assert script.invoked("network", "rm")


def test_verification_drift_extra_accept_destroys_sandbox() -> None:
    drifted = RULE_DUMP_OK + "\n-A OUTPUT -d 203.0.113.9/32 -j ACCEPT"
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    script.queue(("run", "-d"), script.ok(stdout="cid\n"))
    script.queue(("inspect",), script.ok(stdout="true\n"))
    script.queue(("exec",), script.ok())  # v4 install
    script.queue(("exec",), script.ok())  # v6 install
    script.queue(("exec",), script.ok(stdout=drifted + "\n"))  # v4 dump
    script.queue(("exec",), script.ok(stdout=RULE_DUMP_V6_OK + "\n"))  # v6 dump
    sandbox = _sandbox(script)

    with pytest.raises(SandboxVerificationFailedError, match="unexpected accepts"):
        sandbox.establish()

    assert not sandbox.established
    assert script.invoked("rm", "-f")


def test_verification_missing_allow_rule_fails_closed() -> None:
    missing = "\n".join(
        [
            "-P OUTPUT DROP",
            "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
    )
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    script.queue(("run", "-d"), script.ok(stdout="cid\n"))
    script.queue(("inspect",), script.ok(stdout="true\n"))
    script.queue(("exec",), script.ok())  # v4 install (scripted success)
    script.queue(("exec",), script.ok())  # v6 install
    script.queue(("exec",), script.ok(stdout=missing + "\n"))  # v4 dump disagrees
    script.queue(("exec",), script.ok(stdout=RULE_DUMP_V6_OK + "\n"))  # v6 dump
    sandbox = _sandbox(script)

    with pytest.raises(SandboxVerificationFailedError, match="missing accepts"):
        sandbox.establish()


def test_non_drop_policy_fails_verification() -> None:
    permissive = "\n".join(
        [
            "-P OUTPUT ACCEPT",
            f"-A OUTPUT -d {TARGET}/32 -j ACCEPT",
        ]
    )
    script = ScriptedDocker()
    script.queue(("image", "inspect"), script.ok())
    script.queue(("network", "create"), script.ok())
    script.queue(("run", "-d"), script.ok(stdout="cid\n"))
    script.queue(("inspect",), script.ok(stdout="true\n"))
    script.queue(("exec",), script.ok())  # v4 install
    script.queue(("exec",), script.ok())  # v6 install
    script.queue(("exec",), script.ok(stdout=permissive + "\n"))  # v4 dump
    script.queue(("exec",), script.ok(stdout=RULE_DUMP_V6_OK + "\n"))  # v6 dump
    sandbox = _sandbox(script)

    with pytest.raises(SandboxVerificationFailedError, match="not DROP"):
        sandbox.establish()


def test_context_manager_destroys_on_success_and_on_failure() -> None:
    script = ScriptedDocker()
    _script_happy_path(script)
    sandbox = _sandbox(script)
    with sandbox as entered:
        assert entered is sandbox
        assert sandbox.established
    assert not sandbox.established

    failing = ScriptedDocker()
    failing.queue(("image", "inspect"), failing.ok())
    failing.queue(("network", "create"), failing.ok())
    failing.queue(("run", "-d"), failing.fail(stderr="nope"))
    broken = _sandbox(failing)
    with pytest.raises(SandboxSetupFailedError), broken:
        pass  # establish() raises on __enter__
    assert not broken.established

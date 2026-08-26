"""Docker-backed egress sandbox: real network-level enforcement (ADR-0003).

Enforcement mechanism — NOT an application-layer check:

1. An isolated bridge network is created per scan attempt.
2. A disposable container starts on that network with ``CAP_NET_ADMIN``.
3. The container's OUTPUT chain is set to policy DROP; the ONLY accepts are
   ESTABLISHED/RELATED replies and per-destination rules for exactly the
   validated binding's addresses (/32 and /128). The kernel drops every
   other packet — including loopback, RFC1918, link-local/metadata, ULA,
   multicast, reserved ranges, and unrelated public IPs — regardless of
   what the workload attempts.
4. Verification re-reads the live rule dump and compares the accepted
   destination SET against the policy; any drift destroys the sandbox and
   fails closed.

The validated binding is the single source of truth for the allow-list:
this class accepts a :class:`SandboxEgressPolicy`, which can only be
derived from a binding.

Capability note (static guard): this module intentionally uses
``subprocess`` to drive the Docker CLI. It opens no sockets of its own;
all traffic originates inside the isolated runtime it creates.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.domain.errors import (
    SandboxSetupFailedError,
    SandboxUnavailableError,
    SandboxVerificationFailedError,
)
from src.scanning.sandbox.base import ExecResult, SandboxVerification

if TYPE_CHECKING:
    from collections.abc import Sequence

    from src.scanning.sandbox.policy import SandboxEgressPolicy

_ACCEPT_DEST_RE = re.compile(r"-A OUTPUT .*-d (\S+) -j ACCEPT")

# Injectable low-level runner for hermetic unit tests; production binds
# subprocess.run directly. Kept narrow so fakes are trivial to script.
DockerCommandRunner = Callable[[list[str], float], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class DockerSandboxConfig:
    """Runtime parameters for :class:`DockerEgressSandbox`."""

    image: str = "sentinelgpt/scanner-sandbox:latest"
    docker_bin: str = "docker"
    resource_prefix: str = "sgpt-sbx"
    exec_timeout_s: float = 30.0
    # Container/network creation can be slow on a cold or busy daemon;
    # a generous ceiling here only delays fail-closed, never bypasses it.
    create_timeout_s: float = 120.0
    startup_timeout_s: float = 20.0
    # UID all WORKLOAD commands run as (``docker exec -u``). Rules are
    # installed and verified as root during establishment; afterwards every
    # exec drops to this unprivileged identity. Empirically verified: Docker
    # sets no ambient capabilities, so a non-root exec yields CapEff=0 —
    # CAP_NET_ADMIN is unavailable to workloads and iptables mutation fails
    # with EPERM while the kernel firewall stays authoritative.
    workload_uid: int | None = 65534
    # Existing networks the sandbox container additionally joins (e.g. a
    # test fixture's seeded-target network). Egress remains constrained by
    # the OUTPUT chain on every attached interface.
    extra_networks: tuple[str, ...] = ()
    # Unit tests inject a fake runner and disable host binary probing.
    check_docker_binary: bool = True


class DockerEgressSandbox:
    """One isolated container whose egress equals one validated binding."""

    def __init__(
        self,
        policy: SandboxEgressPolicy,
        *,
        config: DockerSandboxConfig | None = None,
        command_runner: DockerCommandRunner | None = None,
    ) -> None:
        self._policy = policy
        self._config = config or DockerSandboxConfig()
        self._run_command: DockerCommandRunner = command_runner or _default_runner
        self._network: str | None = None
        self._container: str | None = None
        # Name chosen BEFORE creation so a client-side timeout (where the
        # daemon may still have created the resource) can be reaped.
        self._pending_container: str | None = None
        self._is_established = False
        self._verification: SandboxVerification | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    @property
    def established(self) -> bool:
        return self._is_established

    @property
    def policy(self) -> SandboxEgressPolicy:
        return self._policy

    def establish(self) -> SandboxVerification:
        """Create the isolated runtime and install the binding policy."""
        if self._is_established:
            raise SandboxSetupFailedError("sandbox already established")
        self._preflight()
        try:
            self._create_network()
            self._create_container()
            self._install_egress_rules()
            verification = self.verify()
            self._verify_privilege_drop()
        except Exception:
            self._is_established = False
            self._destroy_quietly()
            raise
        self._verification = verification
        self._is_established = True
        return verification

    def verify(self) -> SandboxVerification:
        """Re-read live netfilter state and compare against the policy."""
        if self._container is None:
            raise SandboxVerificationFailedError("no container to verify")
        rule_dump = self._read_rule_dump()
        v6_dump = self._read_rule_dump(ipv6=True)
        dump = rule_dump + v6_dump
        problems = self._compare_against_policy(rule_dump, v6_dump)
        if problems:
            self._is_established = False
            self.destroy()
            raise SandboxVerificationFailedError("; ".join(problems))
        return SandboxVerification(
            rule_dump=tuple(dump),
            default_drop=True,
            allowed_addresses=frozenset(self._policy.allowed_addresses),
            workload_uid=self._config.workload_uid,
        )

    def _verify_privilege_drop(self) -> None:
        """Prove workloads are unprivileged BEFORE the sandbox counts as up.

        Fail-closed: establishment only succeeds when (a) execs run as the
        configured UID and (b) that identity CANNOT read or mutate netfilter.
        The kernel keeps enforcing the installed OUTPUT rules regardless —
        capabilities govern rule CHANGES, never packet filtering itself.
        """
        if self._config.workload_uid is None:
            return  # explicit opt-out for exotic images; documented gap
        identity = self._exec(["id", "-u"])
        if not identity.succeeded or identity.stdout.strip() != str(self._config.workload_uid):
            self._is_established = False
            self.destroy()
            raise SandboxVerificationFailedError(
                f"workload did not drop to uid {self._config.workload_uid}: "
                f"got {identity.stdout.strip()!r} (exit {identity.exit_code})"
            )
        mutation_probe = self._exec(["iptables", "-w", "-S", "OUTPUT"])
        if mutation_probe.succeeded:
            self._is_established = False
            self.destroy()
            raise SandboxVerificationFailedError(
                "unprivileged workload could read netfilter; capability "
                "drop is not effective on this runtime"
            )

    def _exec_argv(self, argv: Sequence[str]) -> list[str]:
        base = ["exec"]
        if self._config.workload_uid is not None:
            base += ["-u", str(self._config.workload_uid)]
        assert self._container is not None
        return [self._config.docker_bin, *base, self._container, *argv]

    def _exec(self, argv: Sequence[str]) -> ExecResult:
        """Ungated exec used by establishment-time probes only."""
        assert self._container is not None
        started = time.monotonic()
        try:
            completed = self._run_command(self._exec_argv(argv), self._config.exec_timeout_s)
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - started
            return ExecResult(
                argv=tuple(argv),
                exit_code=124,
                stdout="",
                stderr=f"exec exceeded {self._config.exec_timeout_s}s",
                duration_s=duration,
            )
        duration = time.monotonic() - started
        return ExecResult(
            argv=tuple(argv),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_s=duration,
        )

    def run(self, argv: Sequence[str]) -> ExecResult:
        """Execute one command inside the sandbox (the only exec path)."""
        if not self._is_established or self._container is None:
            raise SandboxUnavailableError("sandbox is not established")
        return self._exec(argv)

    def destroy(self) -> None:
        """Tear down all resources. Idempotent; never marks established."""
        self._is_established = False
        if self._pending_container is not None:
            # A timed-out create may still have materialized daemon-side;
            # reap it by its pre-chosen name so nothing orphans.
            self._best_effort(["rm", "-f", self._pending_container])
            self._pending_container = None
        if self._container is not None:
            self._best_effort(["rm", "-f", self._container])
            self._container = None
        if self._network is not None:
            self._best_effort(["network", "rm", self._network])
            self._network = None

    def _destroy_quietly(self) -> None:
        """Cleanup that never masks the in-flight failure."""
        with contextlib.suppress(Exception):
            self.destroy()

    def __enter__(self) -> DockerEgressSandbox:
        if not self._is_established:
            self.establish()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.destroy()

    # ------------------------------------------------------------------ #
    # Establishment internals                                            #
    # ------------------------------------------------------------------ #

    def _preflight(self) -> None:
        if self._config.check_docker_binary and shutil.which(self._config.docker_bin) is None:
            raise SandboxUnavailableError(f"{self._config.docker_bin!r} binary not found")
        inspect = self._docker_or_unavailable(["image", "inspect", self._config.image])
        if inspect.returncode != 0:
            raise SandboxUnavailableError(f"sandbox image missing: {self._config.image}")

    def _create_network(self) -> None:
        name = f"{self._config.resource_prefix}-{uuid.uuid4().hex[:12]}"
        result = self._docker_with_timeout(
            self._config.create_timeout_s,
            ["network", "create", "--driver", "bridge", name],
        )
        if result.returncode != 0:
            self.destroy()
            raise SandboxSetupFailedError(f"network create failed: {result.stderr.strip()}")
        self._network = name

    def _create_container(self) -> None:
        assert self._network is not None
        name = f"{self._config.resource_prefix}-{uuid.uuid4().hex[:12]}"
        self._pending_container = name
        result = self._docker_with_timeout(
            self._config.create_timeout_s,
            [
                "run",
                "-d",
                "--name",
                name,
                "--network",
                self._network,
                "--cap-add",
                "NET_ADMIN",
                self._config.image,
                "sleep",
                "infinity",
            ],
        )
        if result.returncode != 0:
            self.destroy()
            raise SandboxSetupFailedError(f"container start failed: {result.stderr.strip()}")
        self._pending_container = None
        self._container = name
        for extra in self._config.extra_networks:
            attached = self._docker_with_timeout(
                self._config.create_timeout_s, ["network", "connect", extra, name]
            )
            if attached.returncode != 0:
                raise SandboxSetupFailedError(
                    f"joining network {extra} failed: {attached.stderr.strip()}"
                )
        self._await_running()

    def _await_running(self) -> None:
        assert self._container is not None
        deadline = time.monotonic() + self._config.startup_timeout_s
        while time.monotonic() < deadline:
            state = self._docker_or_setup_failed(
                ["inspect", "-f", "{{.State.Running}}", self._container]
            )
            if state.returncode == 0 and state.stdout.strip() == "true":
                return
            time.sleep(0.2)
        raise SandboxSetupFailedError("sandbox container did not start in time")

    def _install_egress_rules(self) -> None:
        assert self._container is not None
        # IPv4: drop everything except established replies and the binding.
        v4_accepts = [f"{address}/32" for address in self._policy.allowed_v4]
        v4_script = _iptables_script("iptables", v4_accepts)
        installed = self._docker_or_setup_failed(["exec", self._container, "sh", "-c", v4_script])
        if installed.returncode != 0:
            raise SandboxSetupFailedError(f"ipv4 egress install failed: {installed.stderr.strip()}")
        # IPv6 is dropped UNCONDITIONALLY — even with no v6 destinations —
        # because leaving the v6 chain at its default ACCEPT would hand
        # workloads an unfiltered side door next to a locked-down v4 chain.
        v6_accepts = [f"{address}/128" for address in self._policy.allowed_v6]
        v6_script = _iptables_script("ip6tables", v6_accepts)
        installed6 = self._docker_or_setup_failed(["exec", self._container, "sh", "-c", v6_script])
        if installed6.returncode != 0:
            raise SandboxSetupFailedError(
                f"ipv6 egress install failed: {installed6.stderr.strip()}"
            )

    # ------------------------------------------------------------------ #
    # Verification internals                                             #
    # ------------------------------------------------------------------ #

    def _read_rule_dump(self, *, ipv6: bool = False) -> tuple[str, ...]:
        assert self._container is not None
        tool = "ip6tables" if ipv6 else "iptables"
        result = self._docker_or_setup_failed(["exec", self._container, tool, "-S", "OUTPUT"])
        if result.returncode != 0:
            raise SandboxVerificationFailedError(f"{tool} dump failed: {result.stderr.strip()}")
        return tuple(line for line in result.stdout.splitlines() if line.strip())

    def _compare_against_policy(
        self, v4_dump: tuple[str, ...], v6_dump: tuple[str, ...]
    ) -> list[str]:
        problems: list[str] = []
        expected_v4 = {f"{a}/32" for a in self._policy.allowed_v4}
        expected_v6 = {f"{a}/128" for a in self._policy.allowed_v6}
        for dump, expected, tool in (
            (v4_dump, expected_v4, "iptables"),
            (v6_dump, expected_v6, "ip6tables"),
        ):
            if not any(line.startswith("-P OUTPUT DROP") for line in dump):
                problems.append(f"{tool}: OUTPUT policy is not DROP")
            accepted = {match.group(1) for line in dump if (match := _ACCEPT_DEST_RE.search(line))}
            unexpected = accepted - expected
            missing = expected - accepted
            if unexpected:
                problems.append(f"{tool}: unexpected accepts {sorted(unexpected)}")
            if missing:
                problems.append(f"{tool}: missing accepts {sorted(missing)}")
        return problems

    # ------------------------------------------------------------------ #
    # Docker plumbing                                                    #
    # ------------------------------------------------------------------ #

    def _argv(self, args: Sequence[str]) -> list[str]:
        return [self._config.docker_bin, *args]

    def _docker(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return self._run_command(self._argv(args), self._config.exec_timeout_s)

    def _docker_with_timeout(
        self, timeout_s: float, args: Sequence[str]
    ) -> subprocess.CompletedProcess[str]:
        """Docker call with an explicit ceiling (slow-create tolerance)."""
        try:
            return self._run_command(self._argv(args), timeout_s)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxSetupFailedError(f"cannot invoke docker: {exc}") from exc

    def _docker_or_unavailable(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._docker(args)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxUnavailableError(f"cannot invoke docker: {exc}") from exc

    def _docker_or_setup_failed(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._docker(args)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxSetupFailedError(f"cannot invoke docker: {exc}") from exc

    def _best_effort(self, args: Sequence[str]) -> None:
        # Best-effort teardown: resource may already be gone or hung.
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            self._docker(args)


def _iptables_script(tool: str, accepts: list[str]) -> str:
    parts = [
        f"{tool} -P OUTPUT DROP",
        f"{tool} -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        *[f"{tool} -A OUTPUT -d {dest} -j ACCEPT" for dest in accepts],
    ]
    return " && ".join(parts)


def _default_runner(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed docker CLI prefix, no shell
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )

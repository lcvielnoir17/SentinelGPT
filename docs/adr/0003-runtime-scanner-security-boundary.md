# ADR-0003: Runtime Scanner Security Boundary (Egress Enforcement)

**Status:** Accepted (sandbox enforcement implemented and integration-proven on the supported runtime; scanner execution remains BLOCKED — see control status)
**Date:** 2026-08-26
**Extends:** ADR-0001, ADR-0002

## Context

ADR-0001 fixed the SSRF layering: registration-time checks are lexical only;
scan-time DNS re-resolution and NETWORK-level egress enforcement are
mandatory before any scanner executes. ADR-0002 delivered the application
half of that model (IP policy over every resolved A/AAAA record, validated
bindings, deny-by-default egress contexts, redirect revalidation, an engine
execution gate) and stated plainly why a Python policy object cannot
constrain code that ignores it:

> A Python policy object cannot constrain code that ignores it … Defense
> therefore terminates in a NETWORK mechanism.

Phase 2 builds that network mechanism. Without it, any future engine bug or
bypass could reach loopback services, RFC1918 neighbours, cloud metadata
(169.254.169.254), or arbitrary unrelated public IPs from inside the trust
boundary — the exact class of incident scan-time validation exists to
prevent, including via DNS rebinding between validation and connection.

## Decision

### 1. Real DNS I/O enters the codebase in exactly one place

`src/infrastructure/network/dns_resolver.PlatformDnsResolver` implements the
ADR-0002 `HostnameResolver` contract using fresh `socket.getaddrinfo`
(AF_UNSPEC): every A **and** AAAA record, deduplicated, deterministically
ordered, never cached, with platform errno families (POSIX `EAI_*`, Windows
`WSA*`) mapped onto the three typed failure kinds. It duplicates no IP-policy
logic; admission stays entirely in the domain layer.

### 2. Egress is enforced by the kernel inside a disposable sandbox

`DockerEgressSandbox` (`src/scanning/sandbox/docker_sandbox.py`) gives each
scan attempt:

1. a dedicated bridge network,
2. a throwaway container started with `CAP_NET_ADMIN`,
3. its netfilter OUTPUT chain set to policy **DROP**, accepting ONLY
   ESTABLISHED/RELATED replies plus per-destination rules for exactly the
   validated binding's addresses (`/32` for v4, `/128` for v6),
4. **unconditional IPv6 DROP** even when no v6 destinations exist — leaving
   the v6 chain at ACCEPT would be an unfiltered side door beside a locked
   v4 chain,
5. post-install verification that re-reads `iptables -S OUTPUT` /
   `ip6tables -S OUTPUT` and compares the accepted destination SET against
   the requested policy; any drift (non-DROP policy, unexpected accepts,
   missing accepts) destroys the sandbox and fails closed.

The allow-list is derived exclusively from the binding:
`SandboxEgressPolicy.for_binding()` is the sole constructor (direct or empty
construction raises), so no caller can hand the sandbox an independent
destination list. `run(argv)` is the only way to execute anything inside;
the context manager always tears down, including on engine failure.

This is NOT an application-level check in front of requests: denied packets
are dropped by the kernel before they leave the container, regardless of
what the workload attempts. Integration tests launch real connects and
assert denial.

### 3. The execution chain is ordered and gated end-to-end

`SandboxedScanExecutor.execute_scan` is the only sanctioned path:

```
fresh resolve_all -> validate EVERY A/AAAA -> ValidatedTargetBinding
  -> SandboxEgressPolicy -> sandbox establish -> verify
  -> require_scan_context -> ENGINE GATE -> (future) engine.execute
```

Every step is mandatory and fail-closed; every exit path destroys the
sandbox. The ENGINE GATE still raises `SCANNER_EXECUTION_BLOCKED` (501)
because **no engine implementation exists**; opening that gate is a future,
deliberate, reviewed act that additionally requires production-runtime
parity (below).

## Sandbox lifecycle

```
create (network + container, pre-chosen names)
  -> install binding-derived OUTPUT rules
  -> verify live rule dump == policy
  -> run scanner workload via exec (only path)
  -> collect result
  -> destroy (container + network; also reaps daemon-side orphans whose
     client-side create timed out)
```

Failure behavior:

| Failure | Result |
|---|---|
| Docker CLI/daemon/image missing | `SANDBOX_UNAVAILABLE` — nothing runs |
| Create/install error | cleanup + `SANDBOX_SETUP_FAILED` |
| Client timeout during create | pre-chosen names reaped; no orphans |
| Verification drift | destroy + `SANDBOX_VERIFICATION_FAILED` |
| Exec before establishment | refused (`require_established`) |
| Engine raises | `finally` destroys sandbox |

## Evidence of enforcement

`tests/integration/test_sandbox_enforcement.py` seeds internal listeners on
an isolated network and launches REAL TCP connects from inside the sandboxed
container: the authorized target round-trips through the sandbox while
loopback, an RFC1918 peer WITH a live listener, TEST-NET unrelated public,
cloud metadata, other RFC1918 space, IPv6 ULA, IPv6 loopback, and the
unspecified address are all kernel-denied. Additional proofs: rule-dump
receipts show `-P OUTPUT DROP` on both families; redirect escape is blocked
at BOTH the domain layer and the runtime layer; DNS-rebinding drift is
detected in-domain AND denied by the frozen allow-list; changed bindings
deny previously authorized targets; destroyed sandboxes refuse execution;
success/failure teardown leaves zero leftover resources. No external host is
contacted by any test.

## Supported runtime assumptions (honest scope)

Enforcement as implemented requires:

* a Linux-container runtime (verified locally on Docker Desktop / WSL2,
  linux/amd64);
* the `sentinelgpt/scanner-sandbox:latest` image built from
  `infra/docker/scanner-sandbox.Dockerfile` (python:3.12-slim + iptables;
  build scripts in `scripts/`);
* `--cap-add NET_ADMIN` for the userspace iptables installation.

Known gaps, deliberately recorded rather than hidden:

1. **Root + NET_ADMIN container**: rule installation needs root today; a
   later phase should drop workload privileges after setup (e.g.
   `setpriv`/user switch inside the container).
2. **Production parity**: Kubernetes/containerd equivalents of this exact
   DROP-with-allowlist model are not yet wired; running scanners outside a
   sandbox-established container remains forbidden by the gate.
3. **No HTTP-layer yet**: redirects are proven at the policy level with
   synthetic/simulated destinations; the future HTTP client must consume
   the pinned destination from its context (ADR-0002 contract).
4. **In-process object seams**: like all Python objects, the policy can be
   reached via `object.__setattr__`; authoritative containment is the
   kernel boundary, not memory safety.

## Consequences

* The application half (ADR-0002) and the runtime half (this ADR) now agree:
  validated IPs become the machine-enforced allow-list, and drift anywhere
  fails closed.
* Scanner execution stays BLOCKED until real engines land behind this chain
  AND negative egress tests run in CI against the same mechanism.

## Control status

| Control | Status |
|---|---|
| Fresh complete DNS resolution (all A+AAAA) | **IMPLEMENTED** (real adapter, hermetically tested) |
| IP policy over every record | **IMPLEMENTED** (unchanged from ADR-0002) |
| Binding-derived sandbox allow-list | **IMPLEMENTED** (single sealed constructor) |
| Kernel egress enforcement (v4+v6 DROP + accepts) | **IMPLEMENTED + INTEGRATION-PROVEN** on supported runtime |
| Post-install verification (rule-dump equality) | **IMPLEMENTED** |
| Fail-closed lifecycle incl. orphan reaping | **IMPLEMENTED** |
| Redirect revalidation (policy/service) | **IMPLEMENTED** (synthetic destinations) |
| Engine execution gate | **IMPLEMENTED — STILL BLOCKS ALL EXECUTION** |
| Privilege drop inside sandbox | **NOT IMPLEMENTED** |
| Production orchestrator parity (k8s/containerd) | **NOT IMPLEMENTED** |
| Real engines / HTTP layer | **NOT IMPLEMENTED — Phase 3+** |

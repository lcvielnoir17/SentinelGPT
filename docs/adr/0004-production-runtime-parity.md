# ADR-0004: Production Runtime Parity for the Scan Sandbox

**Status:** Accepted (design; implementation deferred until a production Linux runtime is the deployment target)
**Date:** 2026-08-26
**Extends:** ADR-0003

## Context

ADR-0003's enforcement is implemented and integration-proven on
Docker Desktop / WSL2 (linux/amd64). Production will run on a real Linux
host, most plausibly Kubernetes with containerd. Before writing any cluster
code we must confirm the architecture does NOT embed Docker assumptions in
scanner-domain code.

## Assessment: the boundary is already clean

Audited surfaces (`sandbox/base.py`, `docker_sandbox.py`, `policy.py`,
`runner.py`, domain contracts):

* The scanner domain knows only `ValidatedTargetBinding`,
  `SandboxEgressPolicy`, and the `EgressSandbox` Protocol. `grep` confirms
  no Docker references outside `scanning/sandbox/`.
* Orchestration depends exclusively on `SandboxFactory =
  Callable[[SandboxEgressPolicy], EgressSandbox]` (now defined canonically
  in `sandbox/base.py`). Swapping runtimes is a wiring change at composition
  root — no domain edits.
* `DockerEgressSandbox` is one producer of that factory, confined to its
  module by the static boundary guard (process capability allowed ONLY
  there).

Conclusion: **no abstraction change is required beyond formalizing
`SandboxFactory`; Kubernetes/containerd support is additive.**

## Requirements every runtime implementation MUST satisfy

1. Accept only `SandboxEgressPolicy` derived from a validated binding.
2. Establish → install per-destination egress rules → VERIFY live state
   against the policy → only then report established.
3. Fail closed with the ADR-0003 error family
   (`SANDBOX_UNAVAILABLE` / `SANDBOX_SETUP_FAILED` /
   `SANDBOX_VERIFICATION_FAILED`) and clean up all resources.
4. Expose exec-only workload execution as an unprivileged identity, with a
   post-setup capability probe proving netfilter is immutable to workloads.
5. Idempotent teardown; orphan reaping after partial creation.

## Kubernetes/containerd shape (design sketch — not implemented)

Preferred: **init-container sharing the workload pod's network namespace**
(`shareProcessNamespace` irrelevant; `containers[].securityContext.capabilities.add:
[NET_ADMIN]` on init only). Init installs OUTPUT DROP + binding accepts via
iptables inside the shared netns, then exits; verification runs `iptables -S`
through a second short container in the same netns BEFORE the workload
container is unblocked (pod init gating). Workload container carries NO extra
capabilities; UID restricted via `runAsNonRoot` + `runAsUser`. Egress to the
validated IPs must additionally be routable: either host-routed (Node-level)
or a CNI plugin permitting pod→target egress while NetworkPolicy denies
everything else — the kernel rules remain the authoritative per-scan
allow-list exactly as in Docker.

Alternative rejected for now: pure `NetworkPolicy` allow-listing (control-plane
latency per scan; weaker per-pod guarantees; harder drift verification).

## Consequences

* Docker remains the development/CI runtime with zero special-casing above
  the factory seam.
* Cluster support lands later as one new sandbox module + composition-root
  wiring + the same integration proof suite pointed at seeded in-cluster
  listeners.

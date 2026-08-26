# ADR-0006: Sandbox-Aware HTTP Transport

**Status:** Implemented (live-kernel proven against seeded local targets; scanner execution remains BLOCKED)
**Date:** 2026-08-26
**Extends:** ADR-0003/0004/0005

## Decision

The real HTTP transport is `SandboxHttpClient` +
`http_workload.py`, split across the sandbox boundary:

* **Host side** (`http_transport.py`): validates envelopes, owns redirects,
  serializes specs, parses marker-framed results. Opens NO sockets and
  resolves NO names itself.
* **Container side** (`http_workload.py`, base64-injected via
  `sandbox.run(["python","-I","-c",WORKLOAD_EXEC_CODE,"--spec-b64",...])`)
  executes as the unprivileged workload UID inside the established sandbox;
  every packet is governed by the kernel OUTPUT chain.

The executed code is always byte-identical to the repository source (loader
module hashes nothing today — a future integrity stamp can be added without
protocol change).

## Library & pinned-IP mechanism

Selected **httpx 0.28.1 / httpcore 1.0.9** (already a locked project
dependency). httpcore reads `request.extensions["sni_hostname"]` and passes
it to SSL `server_hostname`, which drives BOTH SNI and certificate hostname
verification. Therefore:

    URL host      = pinned IP (IPv6 bracketed)   → kernel-routed destination
    Host header   = validated hostname           → server-side identity
    sni_hostname  = validated hostname           → SNI + cert verification

Verification is NEVER disabled. Self-signed/test CAs are handled by an
explicit scan-scoped CA pinning channel (`SandboxHttpClient(ca_pem=...)`,
wired into the workload as an ADDITIONAL trust root on top of default
verification); engines cannot supply or alter it.

## Redirect security (runtime)

`follow_redirects=False`; the host side walks hops:

* absolute → `ScanTargetResolutionService.evaluate` (normalize → fresh DNS →
  validate EVERY record → new binding) → transport pins the fresh binding
  (`addresses[0]`, deterministic primary) → NEW `ConnectionTarget` → next
  exec in the same established sandbox;
* relative → same context/pin, path merged via `urllib.parse.urljoin`;
* protocol-relative → blocked (empty scheme fails the scheme gate);
* loops → repeat-location detection ⇒ `RedirectDestinationBlockedError`;
* budget → `HttpLimits.max_redirects` ⇒ blocked envelope;
* **HTTPS→HTTP downgrades are FORBIDDEN** (resolves ADR-0005's open item:
  silent downgrade is a stripping vector; http→https upgrades remain legal);
* hop-by-hop headers stripped between hops; method preserved as-is for
  301/302 (documented simplification).

## Cookies / state

Stateless by design: a fresh client per exchange, no cookie jar anywhere,
nothing persists across hops or attempts. If authenticated scanning is ever
approved, it must arrive as a reviewed contract extension scoped to one
validated context.

## Limits, cancellation, failures

* connect/read ceilings from `HttpLimits` (host clamps ≤30 s each);
* response bodies stream-clamped at `max_response_bytes`
  (`truncated=True` flag; superseding ADR-0005's earlier abort wording);
* cancellation checked before each exchange/hop; IN-FLIGHT abort of one
  exchange is NOT possible cross-process this phase (bounded by read
  timeout) — recorded limitation;
* failures map onto `ControlledTransportError` kinds via full exception-chain
  inspection (cert errors surface even when httpx re-wraps them);
  unmarked workload crashes degrade to sanitized PROTOCOL_ERROR;
* request argv budget: spec >64 KiB b64 rejected before exec.

## Isolation proof

Integration suite runs two scans with different bindings joined to both
seeded networks: B's fully-authorized envelope pushed through A's transport
is refused at A's egress precheck AND dropped by A's kernel rules
(CONNECT_TIMEOUT), while A's own authorized target remains reachable.

# =============================================================================
# SentinelGPT scanner-sandbox runtime image (Phase 2; ADR-0003).
#
# PURPOSE
#   Minimal, disposable execution environment in which scanner workloads run
#   under REAL kernel-level egress enforcement (per-destination netfilter
#   rules installed by src/scanning/sandbox/docker_sandbox.py).
#
# SECURITY PROPERTIES
#   * Starts as root ONLY so NET_ADMIN iptables installation can succeed;
#     scanner workloads executed through the sandbox lifecycle are expected
#     to drop privileges themselves in a later phase (documented gap).
#   * Ships python (for controlled connect-probes / future engines) and the
#     iptables userspace. Nothing else: no shells beyond the base image's sh,
#     no package cache, no build tooling.
#   * The egress allow-list is NEVER baked into the image; it is installed at
#     sandbox-establishment time from the validated target binding.
#
# BUILD (no external pulls beyond the cached python:3.12-slim base):
#   docker build -t sentinelgpt/scanner-sandbox:latest \
#       -f infra/docker/scanner-sandbox.Dockerfile infra/docker
# =============================================================================

FROM python:3.12-slim

# iptables: kernel-level egress enforcement installed by the sandbox lifecycle.
# openssl: enables seeded TLS endpoints in local security fixtures/tests.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables openssl \
    && rm -rf /var/lib/apt/lists/*

# Long-lived placeholder process: the sandbox lifecycle execs workload
# commands against this container instead of managing short-lived runs.
CMD ["sleep", "infinity"]

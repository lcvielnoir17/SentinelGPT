# =============================================================================
# SentinelGPT — scanner worker runtime.
#
# Derived from the API runtime image (sentinelgpt-api) and adds the docker CLI
# so the worker can drive the egress sandbox described in ADR-0003
# (src/scanning/sandbox/docker_sandbox.py). The docker CLI is used purely to
# orchestrate sibling sandbox containers via the host daemon socket; the
# worker itself performs no scans locally.
#
# Why appuser is added to the root group:
#   Docker Desktop (WSL2) exposes /var/run/docker.sock owned by root:gid0.
#   Adding appuser to the existing root group (gid 0) grants socket access
#   without elevating to root for the worker process.
#
# Why a static docker CLI is downloaded:
#   Debian's `docker.io` package ships the daemon (`dockerd`) and helper
#   binaries but no `docker` client CLI. The static release is ~70 MiB and
#   contains only the CLI the sandbox orchestrator needs.
# =============================================================================
FROM sentinelgpt-api

USER root

ARG DOCKER_VERSION=27.5.1

# Install the static docker CLI release (CLI only, no daemon) and place it on
# PATH so `python -m celery` (running as appuser) can invoke it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" \
        -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz \
    && rm -rf /var/lib/apt/lists/* \
    && usermod -aG root appuser \
    && docker --version

USER appuser

CMD ["python", "-m", "celery", "-A", "src.workers.celery_app:celery_app", "worker", "--loglevel=INFO", "--queues=scan", "-n", "sgpt-worker@%h"]
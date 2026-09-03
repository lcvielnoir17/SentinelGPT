#!/usr/bin/env sh
# Builds the scanner-sandbox runtime image (Phase 2; ADR-0003).
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image="sentinelgpt/scanner-sandbox:latest"
docker build -t "$image" -f "$root/infra/docker/scanner-sandbox.Dockerfile" "$root/infra/docker"
echo "Built $image"

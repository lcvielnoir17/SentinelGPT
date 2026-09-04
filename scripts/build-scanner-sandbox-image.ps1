# Builds the scanner-sandbox runtime image (Phase 2; ADR-0003).
# Usage:  powershell -File scripts\build-scanner-sandbox-image.ps1
$ErrorActionPreference = "Stop"
$image = if ($env:SCANNER_SANDBOX_IMAGE) { $env:SCANNER_SANDBOX_IMAGE } else { "sentinelgpt/scanner-sandbox:latest" }
$root = Split-Path -Parent $PSScriptRoot
docker build -t $image -f (Join-Path $root "infra/docker/scanner-sandbox.Dockerfile") (Join-Path $root "infra/docker")
if ($LASTEXITCODE -ne 0) { throw "sandbox image build failed" }
Write-Host "Built $image"

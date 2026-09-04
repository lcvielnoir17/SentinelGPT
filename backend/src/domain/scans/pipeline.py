"""Production composition root for the secure scan pipeline (ADR-0009).

The ONLY module where the Phase 7 execution gate is opened
(``SandboxedScanExecutor(enable_execution=True)``). Everything wired here is
the exact chain proven in Phases 2–6:

    PlatformDnsResolver → ScanTargetResolutionService (fresh DNS + policy)
    → DockerEgressSandbox (kernel deny-by-default, privilege-dropped)
    → sandbox-bound HTTP transport → HttpSecurityAnalysisEngine

The domain service receives this as an opaque ``ScanPipeline``; tests inject
their own implementation instead of bypassing any layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from src.domain.scans.scan_service import ScanPipeline
    from src.scanning.runner import SandboxAwareEngine


class DefaultScanPipeline:
    """Real pipeline: fresh resolution → sandbox → transport → engine."""

    engine_code = "headers-analyzer"

    def __init__(self, *, sandbox_image: str | None = None) -> None:
        from src.domain.scanning.resolution import ScanTargetResolutionService
        from src.infrastructure.network.dns_resolver import PlatformDnsResolver
        from src.scanning.engines.http_analysis import HttpSecurityAnalysisEngine
        from src.scanning.runner import SandboxedScanExecutor
        from src.scanning.sandbox.docker_sandbox import DockerEgressSandbox, DockerSandboxConfig

        resolution = ScanTargetResolutionService(PlatformDnsResolver())
        image = sandbox_image or _configured_sandbox_image()
        self._executor = SandboxedScanExecutor(
            resolution,
            lambda policy: DockerEgressSandbox(policy, config=DockerSandboxConfig(image=image)),
            enable_execution=True,  # ADR-0009: gate OPENED only in this file.
        )
        self._engine = HttpSecurityAnalysisEngine()

    def run(self, *, hostname: str, scheme: str, port: int, path: str) -> Any:
        from src.scanning.engines.services import OriginSpec

        return self._executor.execute_scan(
            hostname,
            engine=cast("SandboxAwareEngine", self._engine),
            origin=OriginSpec(scheme=scheme, port=port or None, path=path),
        )


def _configured_sandbox_image() -> str:
    """Sandbox image from settings (digest-pinned in production via env)."""
    from src.config.settings import get_settings

    return get_settings().scanner_sandbox_image


def build_default_pipeline() -> ScanPipeline:
    """Composition root used by background jobs (never imported by APIs)."""
    return DefaultScanPipeline()

"""Sandbox-image configurability for the production scan pipeline (ADR-0003).

The Docker image the egress sandbox boots must be selectable without a
code change so production can pin an immutable digest
(``name:tag@sha256:<digest>``) via ``SCANNER_SANDBOX_IMAGE`` while local
development keeps tracking ``:latest``.
"""

import src.domain.scans.pipeline as pipeline_module
from src.config.settings import Settings
from src.domain.scans.pipeline import DefaultScanPipeline


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"environment": "test"}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_default_image_matches_settings_default() -> None:
    assert _settings().scanner_sandbox_image == "sentinelgpt/scanner-sandbox:latest"


def test_env_override_reaches_settings() -> None:
    assert (
        _settings(
            scanner_sandbox_image="sentinelgpt/scanner-sandbox:1.4.2@sha256:abc123"
        ).scanner_sandbox_image
        == "sentinelgpt/scanner-sandbox:1.4.2@sha256:abc123"
    )


def test_pipeline_factory_wires_configured_image(mocker) -> None:  # type: ignore[no-untyped-def]
    """The sandbox factory the executor receives must stamp the configured
    image onto every sandbox it builds (no sandbox is booted here — the
    factory is invoked directly with a stand-in policy)."""
    import src.scanning.sandbox.docker_sandbox as sandbox_module

    images: list[str] = []
    real_sandbox = sandbox_module.DockerEgressSandbox

    def _spy(policy, **kwargs):  # type: ignore[no-untyped-def]
        config = kwargs.get("config")
        images.append(config.image if config is not None else "<default>")
        return real_sandbox(policy, **kwargs)

    mocker.patch.object(
        pipeline_module,
        "_configured_sandbox_image",
        return_value="sentinelgpt/scanner-sandbox:9.9.9@sha256:deadbeef",
    )
    mocker.patch.object(sandbox_module, "DockerEgressSandbox", side_effect=_spy)
    built = DefaultScanPipeline()
    factory = built._executor._sandbox_factory

    class _FakePolicy:
        pass

    factory(_FakePolicy())  # type: ignore[arg-type]
    assert images == ["sentinelgpt/scanner-sandbox:9.9.9@sha256:deadbeef"]

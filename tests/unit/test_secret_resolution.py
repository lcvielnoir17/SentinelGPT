"""Unit tests for Secret Manager-backed Gemini key resolution (ADR-0013).

The Secret Manager client is faked at the module boundary, so the policy
(precedence, resource-name validation, caching, failure fallback) is
exercised offline.
"""

import pytest

from src.config.settings import Settings
from src.infrastructure.secrets import resolver
from src.infrastructure.secrets.resolver import (
    get_gemini_api_key,
    is_secret_resource_name,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _clean_cache():
    reset_cache()
    yield
    reset_cache()


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "test",
        "gemini_api_key": "env-key",
        "gemini_api_key_secret": "",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def patch_settings(mocker):  # type: ignore[no-untyped-def]
    def _patch(settings: Settings) -> None:
        mocker.patch.object(resolver, "get_settings", return_value=settings)

    return _patch


# --------------------------------------------------------------------------- #
# Resource name validation                                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "projects/my-proj/secrets/gemini-key/versions/latest",
        "projects/my.proj/secrets/gemini.key/versions/7",
        "projects/p1/secrets/s1/versions/1",
    ],
)
def test_valid_resource_names(name: str) -> None:
    assert is_secret_resource_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "my-key",
        "projects/p1/secrets/s1",  # missing version
        "secrets/s1/versions/latest",
        "projects//secrets/s1/versions/latest",
        "projects/p1/secrets/s1/versions/../../evil",
    ],
)
def test_invalid_resource_names(name: str) -> None:
    assert not is_secret_resource_name(name)


# --------------------------------------------------------------------------- #
# Resolution policy                                                           #
# --------------------------------------------------------------------------- #


def test_env_key_used_when_no_secret_configured(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings())
    mocker.patch.object(
        resolver, "_fetch_from_secret_manager", side_effect=AssertionError("must not fetch")
    )
    assert get_gemini_api_key() == "env-key"
    assert True


def test_secret_manager_takes_precedence(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings(gemini_api_key_secret="projects/p/secrets/gemini/versions/latest"))
    fetch = mocker.patch.object(resolver, "_fetch_from_secret_manager", return_value="sm-key")
    assert get_gemini_api_key() == "sm-key"
    fetch.assert_called_once_with("projects/p/secrets/gemini/versions/latest")


def test_secret_disabled_flag_falls_back_to_env(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(
        _settings(
            gemini_api_key_secret="projects/p/secrets/gemini/versions/latest",
            secret_manager_enabled=False,
        )
    )
    mocker.patch.object(
        resolver,
        "_fetch_from_secret_manager",
        side_effect=AssertionError("must not fetch"),
    )
    assert get_gemini_api_key() == "env-key"


def test_secret_failure_falls_back_to_env(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings(gemini_api_key_secret="projects/p/secrets/gemini/versions/latest"))
    fetch = mocker.patch.object(
        resolver,
        "_fetch_from_secret_manager",
        side_effect=RuntimeError("permission denied"),
    )
    assert get_gemini_api_key() == "env-key"
    fetch.assert_called_once()


def test_invalid_resource_name_never_hits_client(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings(gemini_api_key_secret="not-a-resource"))
    client = mocker.patch.object(
        resolver,
        "_fetch_from_secret_manager",
        side_effect=resolver.InvalidSecretResourceNameError("not-a-resource"),
    )
    assert get_gemini_api_key() == "env-key"
    client.assert_called_once()


def test_positive_result_is_cached(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings(gemini_api_key_secret="projects/p/secrets/gemini/versions/latest"))
    fetch = mocker.patch.object(resolver, "_fetch_from_secret_manager", return_value="sm-key")
    assert get_gemini_api_key() == "sm-key"
    assert get_gemini_api_key() == "sm-key"
    assert fetch.call_count == 1


def test_reset_cache_forces_refetch(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings(gemini_api_key_secret="projects/p/secrets/gemini/versions/latest"))
    fetch = mocker.patch.object(resolver, "_fetch_from_secret_manager", return_value="sm-key")
    get_gemini_api_key()
    reset_cache()
    get_gemini_api_key()
    assert fetch.call_count == 2


def test_reset_cache_clears_secret_flag(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    """Regression: reset_cache must clear the secret/negative TTL selector.

    Before the fix, ``reset_cache`` left ``_cached_is_secret`` set, so a
    failed refetch after a reset inherited the POSITIVE (300s) TTL instead
    of the NEGATIVE (30s) one — a stale outage could linger 10x longer.
    """
    patch_settings(_settings(gemini_api_key_secret="projects/p/secrets/gemini/versions/latest"))
    fetch = mocker.patch.object(resolver, "_fetch_from_secret_manager", return_value="sm-key")
    assert get_gemini_api_key() == "sm-key"
    assert resolver._cached_is_secret is True
    reset_cache()
    assert resolver._cached_key is None
    assert resolver._cached_is_secret is False
    fetch.side_effect = RuntimeError("boom")
    assert get_gemini_api_key() == "env-key"
    assert fetch.call_count == 2
    assert resolver._cached_is_secret is False


def test_whitespace_only_secret_payload_rejected(patch_settings, mocker) -> None:  # type: ignore[no-untyped-def]
    patch_settings(_settings(gemini_api_key_secret="projects/p/secrets/gemini/versions/latest"))

    class _FakePayload:
        data = b"   "

    class _FakeResponse:
        payload = _FakePayload()

    class _FakeClient:
        def access_secret_version(self, name: str) -> object:  # noqa: ARG002 - interface shape
            return _FakeResponse()

    mocker.patch.object(resolver, "_client_factory", return_value=_FakeClient())
    # Falls back to env because the payload is empty after strip.
    assert get_gemini_api_key() == "env-key"

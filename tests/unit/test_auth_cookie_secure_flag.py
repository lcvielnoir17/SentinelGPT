"""Regression test: auth cookies must be usable over plain HTTP in dev.

The previous implementation always set ``Secure=True`` on the auth
cookies, which silently breaks login in any non-HTTPS context
(browsers and the ``httpx`` test client drop the cookie). The fix
gates ``Secure`` on the runtime environment: it is REQUIRED in
staging/production (always behind TLS) and OMITTED in local/test
(plain HTTP dev loop). The chapter 2 §9 invariant is preserved: a
deployed environment never runs without ``Secure``.
"""

from __future__ import annotations

from src.api.routes.auth_routes import _cookie_secure_flag
from src.config.constants import ENV_LOCAL, ENV_PRODUCTION, ENV_STAGING, ENV_TEST
from src.config.settings import get_settings


def test_secure_flag_off_in_local_env() -> None:
    """In local/test, ``Secure`` is off so HTTP login works."""
    settings = get_settings()
    original = settings.environment
    try:
        object.__setattr__(settings, "environment", ENV_LOCAL)
        assert _cookie_secure_flag(settings) is False
        object.__setattr__(settings, "environment", ENV_TEST)
        assert _cookie_secure_flag(settings) is False
    finally:
        object.__setattr__(settings, "environment", original)


def test_secure_flag_on_in_deployed_envs() -> None:
    """In staging/production, ``Secure`` is on so cookies travel only over TLS."""
    settings = get_settings()
    original = settings.environment
    try:
        object.__setattr__(settings, "environment", ENV_STAGING)
        assert _cookie_secure_flag(settings) is True
        object.__setattr__(settings, "environment", ENV_PRODUCTION)
        assert _cookie_secure_flag(settings) is True
    finally:
        object.__setattr__(settings, "environment", original)


def test_secure_flag_follows_active_environment() -> None:
    """The helper reads the current ``settings.environment`` each call.

    A test that mutates ``environment`` between calls must observe the
    new value — not a captured-at-import-time snapshot.
    """
    settings = get_settings()
    original = settings.environment
    try:
        object.__setattr__(settings, "environment", ENV_LOCAL)
        assert _cookie_secure_flag(settings) is False
        object.__setattr__(settings, "environment", ENV_PRODUCTION)
        assert _cookie_secure_flag(settings) is True
    finally:
        object.__setattr__(settings, "environment", original)

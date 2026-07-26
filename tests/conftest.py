"""Shared pytest fixtures.

The autouse fixture isolates every test from a developer's local ``.env`` file and
from the cached settings singleton, so configuration tests are deterministic
regardless of the host environment.
"""

from collections.abc import Iterator

import pytest

from config.settings import Settings, get_settings

_SOC_ENV_VARS = (
    "SOC_APP_NAME",
    "SOC_ENVIRONMENT",
    "SOC_DEBUG",
    "SOC_LOG_LEVEL",
    "SOC_LOG_JSON",
)


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neutralize any local ``.env`` and clear the settings cache around each test."""
    # Disable reading a developer-local .env so defaults are deterministic.
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    # Remove any SOC_* variables inherited from the host environment.
    for name in _SOC_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()

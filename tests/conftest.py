"""Shared pytest fixtures.

The autouse fixture isolates every test from a developer's local ``.env`` file
and from any ``SOC_*`` application variables in the host environment, so tests
are deterministic. The separate ``SOC_TEST_DATABASE_URL`` (used only by database
integration tests) is intentionally preserved.
"""

import os
from collections.abc import Iterator

import pytest

from config.settings import Settings, get_settings

_PRESERVED = {"SOC_TEST_DATABASE_URL"}


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neutralize any local ``.env`` and ``SOC_*`` vars; clear the settings cache."""
    # Disable reading a developer-local .env so defaults are deterministic.
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    # Remove any SOC_* application variables inherited from the host environment.
    for name in list(os.environ):
        if name.startswith("SOC_") and name not in _PRESERVED:
            monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()

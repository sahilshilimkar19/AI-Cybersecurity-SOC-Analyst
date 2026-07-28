"""Unit tests for config.settings."""

import pytest
from pydantic import ValidationError

from config.settings import Environment, LogLevel, Settings, get_settings


def test_defaults_are_applied() -> None:
    settings = Settings()

    assert settings.app_name == "AI Cybersecurity SOC Analyst"
    assert settings.environment is Environment.LOCAL
    assert settings.debug is False
    assert settings.log_level is LogLevel.INFO
    assert settings.log_json is True
    assert settings.is_production is False


def test_environment_variables_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_ENVIRONMENT", "staging")
    monkeypatch.setenv("SOC_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("SOC_LOG_JSON", "true")
    monkeypatch.setenv("SOC_APP_NAME", "Custom SOC")

    settings = Settings()

    assert settings.environment is Environment.STAGING
    assert settings.log_level is LogLevel.WARNING
    assert settings.log_json is True
    assert settings.app_name == "Custom SOC"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("false", False), ("1", True), ("0", False)],
)
def test_debug_boolean_parsing(monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool) -> None:
    monkeypatch.setenv("SOC_DEBUG", raw)

    assert Settings().debug is expected


def test_invalid_enum_value_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_LOG_LEVEL", "VERBOSE")

    with pytest.raises(ValidationError):
        Settings()


def test_production_with_debug_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_ENVIRONMENT", "production")
    monkeypatch.setenv("SOC_DEBUG", "true")

    with pytest.raises(ValidationError):
        Settings()


def test_production_without_debug_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_ENVIRONMENT", "production")
    monkeypatch.setenv("SOC_DEBUG", "false")
    # Production also requires a non-default JWT secret (Sprint 3 safety check).
    monkeypatch.setenv("SOC_JWT_SECRET", "a-strong-production-jwt-secret-value-0123456789")

    settings = Settings()

    assert settings.is_production is True
    assert settings.debug is False


def test_production_with_default_jwt_secret_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_ENVIRONMENT", "production")
    monkeypatch.setenv("SOC_DEBUG", "false")

    with pytest.raises(ValidationError):
        Settings()


def test_get_settings_is_cached() -> None:
    first = get_settings()
    second = get_settings()

    assert first is second

    get_settings.cache_clear()
    third = get_settings()

    assert third is not first

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


# --- Dashboard settings (Sprint 12) -----------------------------------------


def test_cors_origins_are_parsed_and_trimmed() -> None:
    settings = Settings(cors_allowed_origins="https://soc.example.com , http://localhost:5173 ,")

    assert settings.cors_origins == ["https://soc.example.com", "http://localhost:5173"]


def test_a_wildcard_cors_origin_is_refused() -> None:
    """An API that answers any origin is one an attacker's page can read."""
    with pytest.raises(ValidationError):
        Settings(cors_allowed_origins="*")


def test_a_wildcard_among_real_origins_is_refused_too() -> None:
    with pytest.raises(ValidationError):
        Settings(cors_allowed_origins="https://soc.example.com,*")


def test_a_default_page_size_above_its_own_ceiling_is_refused() -> None:
    """Otherwise the ceiling is documentation rather than a bound."""
    with pytest.raises(ValidationError):
        Settings(investigation_page_size=200, investigation_page_size_max=50)


# --- Notification settings (Sprint 13) --------------------------------------


def test_alerting_is_off_until_a_channel_is_configured() -> None:
    settings = Settings()

    assert settings.alerting_enabled is False
    assert settings.notification_channel_order == []


def test_a_channel_named_without_its_credentials_is_refused() -> None:
    """A failover chain that looks two deep and is one deep fails at the worst moment."""
    with pytest.raises(ValidationError, match="SOC_SLACK_WEBHOOK_URL is required"):
        Settings(notification_channels="slack")


@pytest.mark.parametrize(
    "missing,expected",
    [
        ({"smtp_host": ""}, "SOC_SMTP_HOST is required"),
        ({"smtp_from_address": ""}, "SOC_SMTP_FROM_ADDRESS is required"),
        ({"smtp_recipients": ""}, "SOC_SMTP_RECIPIENTS is required"),
    ],
)
def test_email_requires_everything_it_needs_to_deliver(
    missing: dict[str, str], expected: str
) -> None:
    payload = {
        "notification_channels": "email",
        "smtp_host": "smtp.test",
        "smtp_from_address": "soc@example.com",
        "smtp_recipients": "oncall@example.com",
    }
    payload.update(missing)

    with pytest.raises(ValidationError, match=expected):
        Settings(**payload)  # type: ignore[arg-type]


def test_an_unknown_channel_name_is_refused() -> None:
    """A typo that removes a channel is a typo that removes an alert."""
    with pytest.raises(ValidationError, match="unknown channel"):
        Settings(notification_channels="pagerduty")


def test_a_repeated_channel_is_refused() -> None:
    with pytest.raises(ValidationError, match="more than once"):
        Settings(
            notification_channels="slack,slack",
            slack_webhook_url="https://hooks.slack.test/abc",
        )


def test_a_channel_with_no_adapter_is_refused_rather_than_swallowing_alerts() -> None:
    with pytest.raises(ValidationError, match="no adapter yet"):
        Settings(notification_channels="webhook")


def test_production_requires_tls_on_the_mail_relay() -> None:
    with pytest.raises(ValidationError, match="SOC_SMTP_USE_TLS must be true"):
        Settings(
            environment="production",
            jwt_secret="a-strong-production-jwt-secret-value-0123456789",
            notification_channels="email",
            smtp_host="smtp.test",
            smtp_from_address="soc@example.com",
            smtp_recipients="oncall@example.com",
            smtp_use_tls=False,
        )


def test_a_fully_configured_failover_chain_is_accepted() -> None:
    settings = Settings(
        notification_channels="slack,email",
        slack_webhook_url="https://hooks.slack.test/abc",
        slack_channel="#soc",
        smtp_host="smtp.test",
        smtp_from_address="soc@example.com",
        smtp_recipients="oncall@example.com, backup@example.com",
    )

    assert settings.alerting_enabled is True
    assert settings.email_recipients == ["oncall@example.com", "backup@example.com"]

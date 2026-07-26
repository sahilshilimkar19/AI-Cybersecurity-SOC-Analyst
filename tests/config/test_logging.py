"""Unit tests for config.logging."""

import json

import pytest

from config.logging import configure_logging, get_logger
from config.settings import LogLevel, Settings


def test_configure_logging_runs_without_error() -> None:
    settings = Settings(log_json=False, log_level=LogLevel.INFO)

    configure_logging(settings)
    logger = get_logger("test")

    # Emitting a log event must not raise.
    logger.info("configuration_smoke", component="logging")


def test_console_renderer_emits_event(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(log_json=False, log_level=LogLevel.INFO))

    get_logger("console").info("hello_console", key="value")

    out = capsys.readouterr().out
    assert "hello_console" in out


def test_json_renderer_emits_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(log_json=True, log_level=LogLevel.INFO))

    get_logger("json").info("hello_json", key="value")

    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(line)

    assert payload["event"] == "hello_json"
    assert payload["key"] == "value"
    assert payload["level"] == "info"


def test_level_filters_below_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(log_json=True, log_level=LogLevel.WARNING))

    logger = get_logger("filter")
    logger.info("suppressed_event")
    logger.warning("emitted_event")

    out = capsys.readouterr().out
    assert "suppressed_event" not in out
    assert "emitted_event" in out

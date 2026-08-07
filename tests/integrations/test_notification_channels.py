"""Tests for the outbound channel adapters.

These are the only adapters in the platform that write to the outside world, so
the properties under test are about restraint: a refusal is distinguished from a
failure, a wedged channel stops being tried, our own rate limit does not look
like the provider's fault, and email never becomes HTML.

Every clock is injected, so backoff and recovery are verified rather than slept
through.
"""

import smtplib
from email.message import EmailMessage
from typing import Any

import httpx
import pytest

from config.settings import Settings
from integrations.notifications import (
    EmailChannel,
    SlackChannel,
    UnconfiguredChannel,
    build_channels,
)
from models.enums import NotificationChannel
from models.notification import RenderedMessage

MESSAGE = RenderedMessage(subject="[SOC URGENT/high] Breach", body="something happened")


class FakeClock:
    """A monotonic clock a test advances by hand."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _slack(handler: Any, clock: FakeClock | None = None, **overrides: Any) -> SlackChannel:
    payload: dict[str, Any] = {
        "webhook_url": "https://hooks.slack.test/abc",
        "timeout_seconds": 5.0,
        "rate_limit_per_minute": 60,
        "breaker_failure_threshold": 3,
        "breaker_reset_seconds": 60.0,
        "client": httpx.Client(transport=httpx.MockTransport(handler)),
        "clock": clock or FakeClock(),
    }
    payload.update(overrides)
    return SlackChannel(**payload)


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def _server_error(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, text="internal error")


# --- Unconfigured -----------------------------------------------------------


def test_an_unconfigured_channel_refuses_rather_than_pretending() -> None:
    """A silent no-op would be the worst failure this module could have."""
    channel = UnconfiguredChannel(NotificationChannel.SLACK)

    result = channel.send(recipient="#soc", message=MESSAGE)
    assert result.delivered is False
    assert result.refused is True
    assert "not configured" in result.detail
    assert channel.is_available is False


# --- Slack ------------------------------------------------------------------


def test_slack_delivers_and_reports_it() -> None:
    assert _slack(_ok).send(recipient="#soc", message=MESSAGE).delivered is True


def test_slack_sends_the_rendered_body() -> None:
    seen: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        return httpx.Response(200, text="ok")

    _slack(capture).send(recipient="#soc", message=MESSAGE)
    assert "something happened" in seen["body"]


def test_a_rejected_message_carries_the_reason() -> None:
    """The difference between a fixable misconfiguration and a mystery."""
    result = _slack(lambda request: httpx.Response(404, text="channel_not_found")).send(
        recipient="#soc", message=MESSAGE
    )

    assert result.delivered is False
    assert result.refused is False
    assert "channel_not_found" in result.detail


def test_a_transport_error_is_a_failure_not_a_crash() -> None:
    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    result = _slack(explode).send(recipient="#soc", message=MESSAGE)
    assert result.delivered is False
    assert "transport error" in result.detail


def test_repeated_failures_open_the_circuit_and_stop_the_hammering() -> None:
    channel = _slack(_server_error, breaker_failure_threshold=2)

    channel.send(recipient="#soc", message=MESSAGE)
    channel.send(recipient="#soc", message=MESSAGE)
    third = channel.send(recipient="#soc", message=MESSAGE)

    assert third.refused is True
    assert "circuit is open" in third.detail
    assert channel.is_available is False


def test_a_recovered_channel_closes_its_circuit_again() -> None:
    clock = FakeClock()
    responses = [_server_error, _server_error, _ok]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)(request) if responses else _ok(request)

    channel = _slack(handler, clock=clock, breaker_failure_threshold=2, breaker_reset_seconds=30.0)
    channel.send(recipient="#soc", message=MESSAGE)
    channel.send(recipient="#soc", message=MESSAGE)
    assert channel.is_available is False

    clock.advance(31)
    assert channel.send(recipient="#soc", message=MESSAGE).delivered is True
    assert channel.is_available is True


def test_our_own_rate_limit_is_a_refusal_not_a_channel_failure() -> None:
    """Otherwise a breaker trips on our own governor and never closes again."""
    channel = _slack(_ok, rate_limit_per_minute=1)

    assert channel.send(recipient="#soc", message=MESSAGE).delivered is True
    second = channel.send(recipient="#soc", message=MESSAGE)

    assert second.refused is True
    assert "rate limit" in second.detail
    # The channel itself is healthy; only our budget is spent.
    assert channel.is_available is True


def test_asking_whether_a_channel_is_available_does_not_consume_its_probe() -> None:
    """Reading availability must not spend the single half-open request."""
    clock = FakeClock()
    channel = _slack(
        _server_error, clock=clock, breaker_failure_threshold=1, breaker_reset_seconds=10.0
    )
    channel.send(recipient="#soc", message=MESSAGE)

    clock.advance(11)
    assert channel.is_available is True
    assert channel.is_available is True
    # The probe is still available for the next real send.
    assert channel.send(recipient="#soc", message=MESSAGE).refused is False


# --- Email ------------------------------------------------------------------


class FakeSmtp:
    """A stand-in for the four methods the adapter uses."""

    def __init__(self, *, fail_on: str | None = None) -> None:
        self.fail_on = fail_on
        self.messages: list[EmailMessage] = []
        self.started_tls = False
        self.logged_in = False
        self.quit_called = False

    def starttls(self) -> None:
        if self.fail_on == "starttls":
            raise smtplib.SMTPException("tls refused")
        self.started_tls = True

    def login(self, user: str, password: str) -> None:
        if self.fail_on == "login":
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
        self.logged_in = True

    def send_message(self, message: EmailMessage) -> object:
        if self.fail_on == "send":
            raise smtplib.SMTPRecipientsRefused({"a@example.com": (550, b"no such user")})
        self.messages.append(message)
        return {}

    def quit(self) -> None:
        self.quit_called = True


def _email(transport: FakeSmtp, **overrides: Any) -> EmailChannel:
    payload: dict[str, Any] = {
        "host": "smtp.test",
        "port": 587,
        "username": "soc",
        "password": "secret",
        "use_tls": True,
        "from_address": "soc@example.com",
        "timeout_seconds": 5.0,
        "rate_limit_per_minute": 60,
        "breaker_failure_threshold": 3,
        "breaker_reset_seconds": 60.0,
        "transport_factory": lambda: transport,
        "clock": FakeClock(),
    }
    payload.update(overrides)
    return EmailChannel(**payload)


def test_email_delivers_over_tls_with_credentials() -> None:
    transport = FakeSmtp()

    assert _email(transport).send(recipient="a@example.com", message=MESSAGE).delivered is True
    assert transport.started_tls is True
    assert transport.logged_in is True
    assert transport.quit_called is True


def test_an_alert_email_is_text_plain_and_never_html() -> None:
    """An alert quoting a hostile URL must not arrive as a live link."""
    transport = FakeSmtp()
    _email(transport).send(recipient="a@example.com", message=MESSAGE)

    sent = transport.messages[0]
    assert sent.get_content_type() == "text/plain"
    assert sent.is_multipart() is False


def test_the_subject_and_envelope_are_set_from_the_message() -> None:
    transport = FakeSmtp()
    _email(transport).send(recipient="a@example.com", message=MESSAGE)

    sent = transport.messages[0]
    assert sent["Subject"] == "[SOC URGENT/high] Breach"
    assert sent["From"] == "soc@example.com"
    assert sent["To"] == "a@example.com"


def test_a_message_with_no_subject_still_gets_one() -> None:
    transport = FakeSmtp()
    _email(transport).send(recipient="a@example.com", message=RenderedMessage(body="x"))

    assert transport.messages[0]["Subject"] == "SOC alert"


def test_anonymous_relays_skip_the_login() -> None:
    transport = FakeSmtp()
    _email(transport, username="").send(recipient="a@example.com", message=MESSAGE)

    assert transport.logged_in is False


def test_tls_can_be_omitted_for_a_local_relay() -> None:
    transport = FakeSmtp()
    _email(transport, use_tls=False).send(recipient="a@example.com", message=MESSAGE)

    assert transport.started_tls is False


@pytest.mark.parametrize("stage", ["starttls", "login", "send"])
def test_a_failure_at_any_stage_is_reported_with_its_reason(stage: str) -> None:
    result = _email(FakeSmtp(fail_on=stage)).send(recipient="a@example.com", message=MESSAGE)

    assert result.delivered is False
    assert result.refused is False
    assert "smtp error" in result.detail


def test_a_failure_to_hang_up_does_not_undo_a_delivery() -> None:
    class RudeSmtp(FakeSmtp):
        def quit(self) -> None:
            raise smtplib.SMTPException("connection reset")

    assert _email(RudeSmtp()).send(recipient="a@example.com", message=MESSAGE).delivered is True


def test_a_connection_error_is_a_failure_not_a_crash() -> None:
    def refuse() -> FakeSmtp:
        raise OSError("connection refused")

    channel = _email(FakeSmtp(), transport_factory=refuse)
    result = channel.send(recipient="a@example.com", message=MESSAGE)

    assert result.delivered is False
    assert "smtp error" in result.detail


# --- Composition ------------------------------------------------------------


def test_no_configured_channel_composes_no_adapters() -> None:
    assert build_channels(Settings(log_json=False, log_level="WARNING")) == {}


def test_configured_channels_compose_their_adapters() -> None:
    settings = Settings(
        log_json=False,
        log_level="WARNING",
        notification_channels="slack,email",
        slack_webhook_url="https://hooks.slack.test/abc",
        slack_channel="#soc",
        smtp_host="smtp.test",
        smtp_from_address="soc@example.com",
        smtp_recipients="a@example.com",
    )
    channels = build_channels(settings)

    assert set(channels) == {NotificationChannel.SLACK, NotificationChannel.EMAIL}
    assert channels[NotificationChannel.SLACK].channel is NotificationChannel.SLACK

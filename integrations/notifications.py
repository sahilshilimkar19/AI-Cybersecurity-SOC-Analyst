"""Outbound notification channels (SAD §7; EDS §3.12).

Every other adapter in this package **pulls** — NVD, VirusTotal, GitHub, log
sources are all read-only by design, and SAD §7 says so explicitly. These are the
exception: they push, and a push has an effect in the world that cannot be
retracted. That asymmetry shapes the module.

Nothing here decides whether to send. An adapter is given a rendered message and
a recipient and does exactly that much; the human-approval check lives at the
write boundary, one layer up, where it can be enforced once for every channel
rather than re-implemented per adapter and eventually forgotten in one of them.

Each channel is its own failure domain — its own rate limiter and circuit breaker
— so a wedged SMTP relay does not stop Slack, and an alert storm against one
channel does not become an alert storm against all of them.

The default is :class:`UnconfiguredChannel`, which refuses with a named reason.
An unconfigured deployment therefore reports "no channel configured" rather than
silently succeeding at nothing, exactly as an unconfigured threat-intel provider
reports "unavailable" rather than "clean".
"""

from __future__ import annotations

import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from typing import TYPE_CHECKING, Any, Protocol

import httpx

from config.logging import get_logger
from integrations.resilience import BreakerState, CircuitBreaker, RateLimiter
from models.enums import NotificationChannel

if TYPE_CHECKING:
    from collections.abc import Callable

    from config.settings import Settings
    from models.notification import RenderedMessage

_logger = get_logger(__name__)


@dataclass(frozen=True)
class SendResult:
    """What happened to one message on one channel.

    ``refused`` distinguishes "we did not try" — an open circuit, an exhausted
    rate limit, a missing credential — from "we tried and it failed". Only the
    second is evidence about the channel's health, and treating them alike is how
    a breaker trips on its own refusals and never closes again.
    """

    delivered: bool
    detail: str = ""
    refused: bool = False

    @classmethod
    def ok(cls, detail: str = "") -> SendResult:
        return cls(delivered=True, detail=detail)

    @classmethod
    def failed(cls, detail: str) -> SendResult:
        return cls(delivered=False, detail=detail)

    @classmethod
    def refuse(cls, detail: str) -> SendResult:
        return cls(delivered=False, detail=detail, refused=True)


class NotificationChannelAdapter(Protocol):
    """Deliver one rendered message to one recipient."""

    @property
    def channel(self) -> NotificationChannel: ...
    @property
    def is_available(self) -> bool: ...
    def send(self, *, recipient: str, message: RenderedMessage) -> SendResult: ...


class UnconfiguredChannel:
    """A channel that was asked for but has no credentials behind it.

    Refuses every send with a reason rather than pretending to succeed. A silent
    no-op here would be the worst failure mode the module has: alerts that
    everyone believes are going out, and a delivery log that agrees.
    """

    def __init__(self, channel: NotificationChannel) -> None:
        self._channel = channel

    @property
    def channel(self) -> NotificationChannel:
        return self._channel

    @property
    def is_available(self) -> bool:
        return False

    def send(self, *, recipient: str, message: RenderedMessage) -> SendResult:
        return SendResult.refuse(f"{self._channel.value} is not configured")


class _ResilientChannel:
    """Shared rate limiting and circuit breaking for a real channel."""

    def __init__(
        self,
        channel: NotificationChannel,
        *,
        rate_limit_per_minute: int,
        breaker_failure_threshold: int,
        breaker_reset_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._channel = channel
        self._limiter = RateLimiter(
            capacity=rate_limit_per_minute,
            per_second=rate_limit_per_minute / 60.0,
            clock=clock,
        )
        self._breaker = CircuitBreaker(
            failure_threshold=breaker_failure_threshold,
            reset_seconds=breaker_reset_seconds,
            name=f"notifications:{channel.value}",
            clock=clock,
        )

    @property
    def channel(self) -> NotificationChannel:
        return self._channel

    @property
    def is_available(self) -> bool:
        """Whether the channel is configured and its circuit is not open.

        Reads the breaker's state rather than calling ``allow()``: asking whether
        a channel is usable must not consume the single half-open probe that the
        next real send is going to need.
        """
        return self._breaker.state is not BreakerState.OPEN

    def _guard(self) -> SendResult | None:
        """Refuse before sending when the channel should not be used."""
        if not self._breaker.allow():
            return SendResult.refuse(f"{self._channel.value} circuit is open")
        if not self._limiter.try_acquire():
            # Counted as a refusal, not a failure: being rate limited by our own
            # governor says nothing about whether the channel is healthy.
            return SendResult.refuse(f"{self._channel.value} rate limit exhausted")
        return None

    def _record(self, result: SendResult) -> SendResult:
        if result.delivered:
            self._breaker.record_success()
        elif not result.refused:
            self._breaker.record_failure()
        return result


class SlackChannel(_ResilientChannel):
    """Slack incoming webhook.

    A webhook URL is a bearer capability to post into a channel, so it is treated
    as a secret and never logged, never echoed into a delivery record, and never
    returned by the API.
    """

    def __init__(
        self,
        *,
        webhook_url: str,
        timeout_seconds: float,
        rate_limit_per_minute: int,
        breaker_failure_threshold: int,
        breaker_reset_seconds: float,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            NotificationChannel.SLACK,
            rate_limit_per_minute=rate_limit_per_minute,
            breaker_failure_threshold=breaker_failure_threshold,
            breaker_reset_seconds=breaker_reset_seconds,
            clock=clock,
        )
        self._webhook_url = webhook_url
        self._timeout = timeout_seconds
        self._client = client

    def send(self, *, recipient: str, message: RenderedMessage) -> SendResult:
        refusal = self._guard()
        if refusal is not None:
            return refusal

        try:
            response = self._post({"text": message.body})
        except httpx.HTTPError as exc:
            return self._record(SendResult.failed(f"slack transport error: {type(exc).__name__}"))

        if response.status_code >= 400:
            # Slack returns the reason in the body; it is short and non-sensitive
            # ("invalid_payload", "channel_not_found"), and it is the difference
            # between a fixable misconfiguration and a mystery.
            return self._record(
                SendResult.failed(
                    f"slack rejected the message: {response.status_code} {response.text[:120]}"
                )
            )
        return self._record(SendResult.ok("slack accepted the message"))

    def _post(self, payload: dict[str, str]) -> httpx.Response:
        if self._client is not None:
            return self._client.post(self._webhook_url, json=payload, timeout=self._timeout)
        with httpx.Client(timeout=self._timeout) as client:
            return client.post(self._webhook_url, json=payload)


class SmtpTransport(Protocol):
    """The slice of ``smtplib.SMTP`` this adapter uses.

    Narrow on purpose: a test needs a stand-in for four methods, not for the
    whole of ``smtplib``. Return types are ``Any`` because ``smtplib`` returns
    status tuples that this adapter never reads — it relies on the exceptions,
    which is the part of that API that actually reports failure.
    """

    def starttls(self) -> Any: ...
    def login(self, user: str, password: str) -> Any: ...
    def send_message(self, message: EmailMessage) -> Any: ...
    def quit(self) -> Any: ...


class EmailChannel(_ResilientChannel):
    """SMTP delivery, as ``text/plain`` only.

    Never HTML. An alert routinely quotes a hostile URL or a process command
    line, and an HTML mail renders that as a live link and a script host in one
    step. Plain text costs formatting and buys an alert that cannot act on its
    reader.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool,
        from_address: str,
        timeout_seconds: float,
        rate_limit_per_minute: int,
        breaker_failure_threshold: int,
        breaker_reset_seconds: float,
        transport_factory: Callable[[], SmtpTransport] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            NotificationChannel.EMAIL,
            rate_limit_per_minute=rate_limit_per_minute,
            breaker_failure_threshold=breaker_failure_threshold,
            breaker_reset_seconds=breaker_reset_seconds,
            clock=clock,
        )
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._from_address = from_address
        self._timeout = timeout_seconds
        self._transport_factory = transport_factory

    def send(self, *, recipient: str, message: RenderedMessage) -> SendResult:
        refusal = self._guard()
        if refusal is not None:
            return refusal

        email = EmailMessage()
        email["Subject"] = message.subject or "SOC alert"
        email["From"] = self._from_address
        email["To"] = recipient
        # set_content on a plain str produces text/plain. Nothing in this module
        # ever calls add_alternative, which is what would introduce an HTML part.
        email.set_content(message.body)

        transport: SmtpTransport | None = None
        try:
            transport = self._connect()
            if self._use_tls:
                transport.starttls()
            if self._username:
                transport.login(self._username, self._password)
            transport.send_message(email)
        except (OSError, smtplib.SMTPException) as exc:
            return self._record(SendResult.failed(f"smtp error: {type(exc).__name__}: {exc}"[:200]))
        finally:
            if transport is not None:
                self._quit(transport)

        return self._record(SendResult.ok(f"smtp accepted the message for {recipient}"))

    def _connect(self) -> SmtpTransport:
        if self._transport_factory is not None:
            return self._transport_factory()
        return smtplib.SMTP(self._host, self._port, timeout=self._timeout)

    @staticmethod
    def _quit(transport: SmtpTransport) -> None:
        try:
            transport.quit()
        except (OSError, smtplib.SMTPException):
            # The message may already be delivered; a failure to close the
            # connection politely must not turn a success into a failure.
            _logger.debug("smtp_quit_failed")


def build_channels(
    settings: Settings, *, clock: Callable[[], float] = time.monotonic
) -> dict[NotificationChannel, NotificationChannelAdapter]:
    """Compose an adapter for each configured channel.

    A channel named in configuration without its credentials never reaches here —
    settings validation refuses it at startup — so anything present in the
    returned mapping is genuinely able to deliver.
    """
    adapters: dict[NotificationChannel, NotificationChannelAdapter] = {}
    for channel in settings.notification_channel_order:
        if channel is NotificationChannel.SLACK:
            adapters[channel] = SlackChannel(
                webhook_url=settings.slack_webhook_url.get_secret_value(),
                timeout_seconds=settings.slack_timeout_seconds,
                rate_limit_per_minute=settings.notification_rate_limit_per_minute,
                breaker_failure_threshold=settings.notification_breaker_failure_threshold,
                breaker_reset_seconds=settings.notification_breaker_reset_seconds,
                clock=clock,
            )
        elif channel is NotificationChannel.EMAIL:
            adapters[channel] = EmailChannel(
                host=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password.get_secret_value(),
                use_tls=settings.smtp_use_tls,
                from_address=settings.smtp_from_address,
                timeout_seconds=settings.smtp_timeout_seconds,
                rate_limit_per_minute=settings.notification_rate_limit_per_minute,
                breaker_failure_threshold=settings.notification_breaker_failure_threshold,
                breaker_reset_seconds=settings.notification_breaker_reset_seconds,
                clock=clock,
            )
        else:  # pragma: no cover - settings validation refuses unsupported channels
            adapters[channel] = UnconfiguredChannel(channel)
    return adapters

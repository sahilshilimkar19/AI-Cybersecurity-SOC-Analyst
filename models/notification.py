"""Notification contracts (SAD §3.5, EDS §3.10).

This is the only outbound path the platform has. Everything else in the system
reads the world; this writes to it — a message lands in someone's Slack, someone's
inbox, someone's night. So the rule that governs the module is expressed here as
a **shape** rather than as a policy anyone has to remember:

    An alert cannot be constructed without the identifier of the human decision
    that authorized it.

``AlertRequest.approval_id`` is required and non-optional. There is no default,
no ``None``, and no constructor that omits it — which means no code path can
assemble an alert that nobody approved, and a future contributor who tries will
be stopped by the type rather than by a review comment (invariant #1).

Carrying the id is necessary but not sufficient: the dispatch service still
verifies that the decision exists, belongs to this investigation, and was an
approval. A required field stops the accident; the lookup stops the forgery.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field, model_validator

from models.base import DomainModel, IdentifiedModel
from models.enums import NotificationChannel, NotificationStatus, Severity, TriagePriority

# Bounds on what one alert may carry. A notification is a *pointer* to an
# investigation, not a copy of it: the console holds the detail, and an alert
# that tries to be the report is one that gets truncated by the transport at a
# point nobody chose.
MAX_SUMMARY_CHARACTERS = 1200
MAX_HIGHLIGHTS = 8


class Notification(IdentifiedModel):
    """An outbound alert as persisted.

    ``approval_id`` is required rather than optional: the column behind it is
    NOT NULL, so a notification that no human authorized cannot exist as a row.
    """

    investigation_id: UUID
    approval_id: UUID
    channel: NotificationChannel
    recipient: str
    dedupe_key: str
    priority: TriagePriority = TriagePriority.HIGH
    payload_ref: str | None = None
    status: NotificationStatus = NotificationStatus.PENDING
    delivery_attempts: int = Field(default=0, ge=0)
    failure_reason: str | None = None
    sent_at: datetime | None = None


class AlertTarget(DomainModel):
    """One place an alert may be delivered."""

    channel: NotificationChannel
    recipient: str

    @model_validator(mode="after")
    def _recipient_is_named(self) -> AlertTarget:
        if not self.recipient.strip():
            raise ValueError(f"a {self.channel.value} target must name a recipient")
        return self


class AlertRequest(DomainModel):
    """What to say, about which investigation, on whose authority.

    The approval is not metadata attached to the message — it is a required part
    of what an alert *is*. Every other field describes the incident; this one
    records that a person decided the incident was worth telling someone about.
    """

    investigation_id: UUID
    # No default. An alert with no approval behind it is not a degraded alert,
    # it is a different thing entirely, and the type refuses to represent it.
    approval_id: UUID
    title: str
    summary: str = Field(max_length=MAX_SUMMARY_CHARACTERS)
    priority: TriagePriority
    severity: Severity | None = None
    verdict: str | None = None
    # Short factual lines an on-call reader needs before opening the console:
    # affected hosts, confirmed CVE ids, the count of pending recommendations.
    highlights: list[str] = Field(default_factory=list, max_length=MAX_HIGHLIGHTS)
    # Deep link into the console. The alert says what happened; the console is
    # where someone acts on it, and an alert with no route there is a dead end.
    console_url: str | None = None

    @model_validator(mode="after")
    def _says_something(self) -> AlertRequest:
        if not self.title.strip():
            raise ValueError("an alert must have a title")
        if not self.summary.strip():
            raise ValueError("an alert must say what happened")
        return self


class DeliveryOutcome(DomainModel):
    """What one channel did with one message.

    A failure carries its reason. An alert that failed silently is
    indistinguishable from one that was never attempted, and the difference is
    the whole point of tracking delivery at all.
    """

    channel: NotificationChannel
    recipient: str
    delivered: bool
    attempts: int = Field(default=0, ge=0)
    detail: str = ""
    # True when the channel refused before trying — an open circuit, an
    # exhausted rate limit, a missing credential. Distinguished from a delivery
    # that was attempted and failed, because only one of them means "try again".
    refused: bool = False


class DispatchResult(DomainModel):
    """The outcome of dispatching one alert across the configured channels.

    ``dead_lettered`` is the case the design exists to make impossible to miss:
    every channel failed, nobody was told, and the platform knows it. It is
    reported here, recorded on the row, written to the audit trail, and logged at
    error level — because the one outcome worse than a failed alert is a failed
    alert that nothing noticed.
    """

    investigation_id: UUID
    approval_id: UUID
    outcomes: list[DeliveryOutcome] = Field(default_factory=list)
    deduplicated: list[AlertTarget] = Field(default_factory=list)
    dead_lettered: bool = False
    # Set when no channel is configured at all — a deployment choice, not a
    # failure, and reported separately so the two never look alike.
    no_channel_configured: bool = False

    @property
    def delivered(self) -> bool:
        """Whether at least one channel got the message through."""
        return any(outcome.delivered for outcome in self.outcomes)

    @property
    def attempted(self) -> bool:
        """Whether any channel was actually tried."""
        return bool(self.outcomes)

    @property
    def failed_over(self) -> bool:
        """Whether delivery succeeded only after an earlier channel failed."""
        return self.delivered and any(not outcome.delivered for outcome in self.outcomes)

    @model_validator(mode="after")
    def _dead_letter_means_nothing_got_through(self) -> DispatchResult:
        if self.dead_lettered and self.delivered:
            raise ValueError(
                "a dispatch cannot be dead-lettered and delivered; dead-letter means "
                "every channel failed"
            )
        return self


class RenderedMessage(DomainModel):
    """A message rendered for one channel.

    ``subject`` is empty for channels that have no notion of one. Both fields are
    plain text: nothing here is ever rendered as markup, because an alert about a
    hostile URL that a mail client turns into a clickable link is a self-own.
    """

    subject: str = ""
    body: str

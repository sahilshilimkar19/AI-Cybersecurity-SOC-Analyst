"""Contracts for the notification history and delivery-retry endpoints.

There is deliberately no "send" request shape anywhere in this module. Alerting
is initiated by an approval at the human gate, not by a client asking for a
message to go out — a send endpoint would be a second entrance to the outbound
path, and the whole design depends on there being one.

Retrying is the exception, and a narrow one: it re-attempts a delivery that
*failed*, on the channel and the authority already recorded. Re-sending an alert
someone already received is a new notification and needs a new decision.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from models.enums import NotificationChannel, NotificationStatus, TriagePriority


class NotificationView(BaseModel):
    """One outbound alert and its delivery state.

    ``approval_id`` is non-optional here because the column behind it is NOT
    NULL: an alert nobody authorized cannot exist, so the projection does not
    pretend it might.

    ``failure_reason`` travels with a failed delivery. A dead letter with no
    reason is one an operator cannot act on, and "it failed" is not a reason.
    """

    id: UUID
    investigation_id: UUID
    approval_id: UUID
    channel: NotificationChannel
    recipient: str
    priority: TriagePriority
    status: NotificationStatus
    delivery_attempts: int
    failure_reason: str | None = None
    sent_at: datetime | None = None
    created_at: datetime


class NotificationPage(BaseModel):
    """A page of notification history.

    ``dead_lettered`` is counted across the whole table rather than the page,
    because a queue of undelivered alerts is a standing operational fact and not
    a property of whichever rows a client happened to ask for.
    """

    items: list[NotificationView] = Field(default_factory=list)
    total: int
    limit: int
    offset: int
    dead_lettered: int = 0


class RetryResponse(BaseModel):
    """The outcome of re-attempting one failed delivery."""

    notification_id: UUID
    channel: NotificationChannel
    delivered: bool
    attempts: int
    detail: str = ""
    status: NotificationStatus

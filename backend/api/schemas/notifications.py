"""Read contracts for the notification history screen.

Read-only on purpose. Dispatch — channels, templating, dedupe, failover — is the
Notifications sprint; what exists today is the record a notification leaves
behind, and the screen that shows it. An endpoint that could send would be a
dispatch path that arrived before the post-approval enforcement built to guard it.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from models.enums import NotificationChannel, NotificationStatus


class NotificationView(BaseModel):
    """One outbound alert and its delivery state.

    ``approval_id`` is surfaced rather than hidden: a notification with no linked
    approval is the thing an auditor is looking for, so the screen has to be able
    to show its absence.
    """

    id: UUID
    investigation_id: UUID
    channel: NotificationChannel
    recipient: str
    status: NotificationStatus
    delivery_attempts: int
    approval_id: UUID | None = None
    sent_at: datetime | None = None
    created_at: datetime


class NotificationPage(BaseModel):
    """A page of notification history."""

    items: list[NotificationView] = Field(default_factory=list)
    total: int
    limit: int
    offset: int

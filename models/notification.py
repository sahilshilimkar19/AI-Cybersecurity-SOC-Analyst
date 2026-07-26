"""Notification domain contract."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from models.base import IdentifiedModel
from models.enums import NotificationChannel, NotificationStatus


class Notification(IdentifiedModel):
    """An outbound alert.

    A notification requires a linked human approval before dispatch
    (governing invariant #1); that linkage is enforced by the notification
    service in a later sprint.
    """

    investigation_id: UUID
    channel: NotificationChannel
    recipient: str
    payload_ref: str | None = None
    status: NotificationStatus = NotificationStatus.PENDING
    delivery_attempts: int = Field(default=0, ge=0)
    approval_id: UUID | None = None
    sent_at: datetime | None = None

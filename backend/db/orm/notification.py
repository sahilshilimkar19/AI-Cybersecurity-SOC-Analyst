"""ORM model: notifications."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from models.enums import NotificationChannel, NotificationStatus, TriagePriority


class Notification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An outbound alert, and the human decision that authorized it.

    ``approval_id`` is **NOT NULL**, which is the whole point: a notification
    nobody approved cannot be represented as a row, so invariant #1 is enforced
    by the schema rather than by whichever code path happens to do the insert.

    ``dedupe_key`` is unique. Idempotency is therefore the database's job rather
    than a check-then-act in application code, which under a retry or a race
    would let the same alert page someone twice.
    """

    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("dedupe_key", name="uq_notifications_dedupe_key"),)

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    approval_id: Mapped[UUID] = mapped_column(ForeignKey("human_decisions.id"), index=True)
    channel: Mapped[NotificationChannel] = mapped_column(
        str_enum_column(NotificationChannel, "notification_channel")
    )
    recipient: Mapped[str] = mapped_column(String(320))
    dedupe_key: Mapped[str] = mapped_column(String(64))
    priority: Mapped[TriagePriority] = mapped_column(
        str_enum_column(TriagePriority, "triage_priority"), default=TriagePriority.HIGH
    )
    payload_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[NotificationStatus] = mapped_column(
        str_enum_column(NotificationStatus, "notification_status"),
        default=NotificationStatus.PENDING,
        index=True,
    )
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Why the last attempt failed. Stored because a dead-letter row with no
    # reason is one an operator cannot act on, and "it failed" is not a reason.
    failure_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

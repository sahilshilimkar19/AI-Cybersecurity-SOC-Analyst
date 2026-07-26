"""ORM model: notifications."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from models.enums import NotificationChannel, NotificationStatus


class Notification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An outbound alert; dispatched only after a linked human approval."""

    __tablename__ = "notifications"

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    channel: Mapped[NotificationChannel] = mapped_column(
        str_enum_column(NotificationChannel, "notification_channel")
    )
    recipient: Mapped[str] = mapped_column(String(320))
    payload_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[NotificationStatus] = mapped_column(
        str_enum_column(NotificationStatus, "notification_status"),
        default=NotificationStatus.PENDING,
        index=True,
    )
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    approval_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("human_decisions.id"), nullable=True
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

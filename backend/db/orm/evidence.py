"""ORM model: log_events (immutable evidence)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class LogEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A normalized, provenance-tagged security event. Immutable once written."""

    __tablename__ = "log_events"
    __table_args__ = (
        Index("ix_log_events_investigation_event_time", "investigation_id", "event_time"),
    )

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    asset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("assets.id"), index=True, nullable=True
    )
    source: Mapped[str] = mapped_column(String(255))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(255), index=True)
    raw_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    notability: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

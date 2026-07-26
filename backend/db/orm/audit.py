"""ORM model: audit_logs (append-only, tamper-evident)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base, UUIDPrimaryKeyMixin


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """An immutable audit record of a consequential action.

    Append-only: never updated, versioned, or soft-deleted. ``signature`` is a
    content hash making the entry tamper-evident (SAD §14; hardened with
    cryptographic signing in the Security sprint).
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
        Index("ix_audit_logs_actor_created", "actor_id", "created_at"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor_id: Mapped[UUID | None] = mapped_column(nullable=True)
    action: Mapped[str] = mapped_column(String(255))
    entity_type: Mapped[str] = mapped_column(String(255))
    entity_id: Mapped[UUID | None] = mapped_column(nullable=True)
    before_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    after_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    signature: Mapped[str] = mapped_column(String(128))

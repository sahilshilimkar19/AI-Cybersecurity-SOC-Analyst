"""ORM models: investigations and assets."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    str_enum_column,
)
from models.enums import AssetEnvironment, InvestigationStatus, Severity, TriggerSource


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A host, system, or software involved in investigations."""

    __tablename__ = "assets"

    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    software_inventory: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[AssetEnvironment] = mapped_column(
        str_enum_column(AssetEnvironment, "asset_environment"),
        default=AssetEnvironment.UNKNOWN,
    )


class Investigation(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """The central case record."""

    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigations_status_severity", "status", "severity"),)

    trigger_source: Mapped[TriggerSource] = mapped_column(
        str_enum_column(TriggerSource, "trigger_source")
    )
    status: Mapped[InvestigationStatus] = mapped_column(
        str_enum_column(InvestigationStatus, "investigation_status"),
        default=InvestigationStatus.OPEN,
        index=True,
    )
    severity: Mapped[Severity | None] = mapped_column(
        str_enum_column(Severity, "severity"), nullable=True
    )
    owner_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    summary: Mapped[str | None] = mapped_column(String(), nullable=True)
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    # Which agent stages have run, recorded by the backend as each one finishes.
    # The graph's own transition log lives in its checkpoint, which is keyed by
    # thread and may be in-process; this is the backend's durable record of the
    # same run, and it is what the dashboard reports progress from. Deriving
    # progress from artifacts instead would misreport the honest empty results —
    # research that found no CVEs looks identical to research that never ran.
    pipeline: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

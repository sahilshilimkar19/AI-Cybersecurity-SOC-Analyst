"""ORM models: reports and recommendations."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    str_enum_column,
)
from models.enums import ApprovalStatus, RecommendationType, ReportStatus, TriagePriority


class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A generated incident report; versioned and regenerable from state."""

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("investigation_id", "version", name="uq_reports_investigation_version"),
    )

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    executive_summary: Mapped[str] = mapped_column(String())
    technical_body: Mapped[str] = mapped_column(String())
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        str_enum_column(ReportStatus, "report_status"), default=ReportStatus.DRAFT, index=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class Recommendation(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A prioritized remediation recommendation for human approval (invariant #2)."""

    __tablename__ = "recommendations"

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    action: Mapped[str] = mapped_column(String())
    type: Mapped[RecommendationType] = mapped_column(
        str_enum_column(RecommendationType, "recommendation_type")
    )
    priority: Mapped[TriagePriority] = mapped_column(
        str_enum_column(TriagePriority, "triage_priority"), index=True
    )
    rationale: Mapped[str] = mapped_column(String())
    expected_impact: Mapped[str | None] = mapped_column(String(), nullable=True)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    approval_status: Mapped[ApprovalStatus] = mapped_column(
        str_enum_column(ApprovalStatus, "approval_status"),
        default=ApprovalStatus.PENDING,
        index=True,
    )
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

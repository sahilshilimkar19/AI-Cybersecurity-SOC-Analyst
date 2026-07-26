"""ORM models: threat_assessments and cve_findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    str_enum_column,
)
from models.enums import CveApplicability, EnrichmentStatus, Severity, TriagePriority, Verdict


class ThreatAssessment(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """The Threat Detector's assessment; versioned, prior versions retained."""

    __tablename__ = "threat_assessments"

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    verdict: Mapped[Verdict] = mapped_column(str_enum_column(Verdict, "verdict"))
    severity: Mapped[Severity] = mapped_column(str_enum_column(Severity, "severity"))
    triage_priority: Mapped[TriagePriority] = mapped_column(
        str_enum_column(TriagePriority, "triage_priority")
    )
    enrichment_status: Mapped[EnrichmentStatus] = mapped_column(
        str_enum_column(EnrichmentStatus, "enrichment_status"),
        default=EnrichmentStatus.COMPLETE,
    )
    confidence: Mapped[float] = mapped_column(Float)
    rationale: Mapped[str | None] = mapped_column(String(), nullable=True)
    iocs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    attack_techniques: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class CveFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A CVE identified by the CVE Research agent, with applicability + citations."""

    __tablename__ = "cve_findings"

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    asset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("assets.id"), index=True, nullable=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    cvss: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    summary: Mapped[str | None] = mapped_column(String(), nullable=True)
    applicability: Mapped[CveApplicability] = mapped_column(
        str_enum_column(CveApplicability, "cve_applicability"),
        default=CveApplicability.CANDIDATE,
    )
    exploit_mapping: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    source_freshness: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

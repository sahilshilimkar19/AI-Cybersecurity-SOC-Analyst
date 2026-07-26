"""Incident report and remediation recommendation domain contracts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from models.base import IdentifiedModel
from models.enums import ApprovalStatus, RecommendationType, ReportStatus, TriagePriority
from models.values import Citation


class Report(IdentifiedModel):
    """A generated incident report. Versioned and regenerable from state."""

    investigation_id: UUID
    executive_summary: str
    technical_body: str
    citations: list[Citation] = Field(default_factory=list)
    status: ReportStatus = ReportStatus.DRAFT
    version: int = Field(default=1, ge=1)
    deleted_at: datetime | None = None


class Recommendation(IdentifiedModel):
    """A prioritized remediation recommendation.

    Always framed as a recommendation for human approval; never auto-executed
    (governing invariant #2).
    """

    investigation_id: UUID
    action: str
    type: RecommendationType
    priority: TriagePriority
    rationale: str
    expected_impact: str | None = None
    citations: list[Citation] = Field(default_factory=list)
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    requires_human_approval: bool = True
    version: int = Field(default=1, ge=1)
    deleted_at: datetime | None = None

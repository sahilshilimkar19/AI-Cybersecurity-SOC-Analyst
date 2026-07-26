"""Threat assessment and CVE finding domain contracts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from models.base import IdentifiedModel
from models.enums import (
    CveApplicability,
    EnrichmentStatus,
    Severity,
    TriagePriority,
    Verdict,
)
from models.values import AttackTechnique, Citation, Cvss, Ioc


class ThreatAssessment(IdentifiedModel):
    """The Threat Detector's assessment of an investigation's evidence.

    Revised as an investigation evolves; prior versions are retained
    (``version``).
    """

    investigation_id: UUID
    verdict: Verdict
    severity: Severity
    triage_priority: TriagePriority
    enrichment_status: EnrichmentStatus = EnrichmentStatus.COMPLETE
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str | None = None
    iocs: list[Ioc] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    version: int = Field(default=1, ge=1)
    deleted_at: datetime | None = None


class CveFinding(IdentifiedModel):
    """A CVE identified by the CVE Research agent, with applicability + citations."""

    investigation_id: UUID
    asset_id: UUID | None = None
    cve_id: str
    cvss: Cvss | None = None
    summary: str | None = None
    applicability: CveApplicability = CveApplicability.CANDIDATE
    exploit_mapping: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    source_freshness: datetime | None = None
    version: int = Field(default=1, ge=1)
    deleted_at: datetime | None = None

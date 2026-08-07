"""Request and response contracts for the investigation endpoints.

The request side validates untrusted input at the boundary using the domain
contracts themselves (``RawLogRecord``, ``TimeWindow``, ``AssetContext``), so a
malformed seed is rejected before it reaches the graph rather than surfacing as a
node failure halfway through a run (invariant #3).

The response side is a set of read projections over what the backend persisted.
They are deliberately not the agent outputs: the dashboard renders the record, and
the record is the database. Anything the UI needs in order to present a claim
honestly — the confidence it was held with, the citations behind it, whether
enrichment was even available — travels in the projection, because a field the API
omits is a caveat the screen cannot show.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from models.enums import (
    ApprovalStatus,
    CveApplicability,
    DecisionType,
    EnrichmentStatus,
    InvestigationStatus,
    RecommendationType,
    ReportStatus,
    Severity,
    TriagePriority,
    TriggerSource,
    Verdict,
)
from models.logs import RawLogRecord, TimeWindow
from models.values import Citation
from models.vulnerability import AssetContext

# Bounds on a single seed. They exist so one request cannot pin a worker for
# minutes; a genuinely larger collection is several investigations, or a
# collection job, not one API call.
MAX_SEED_RECORDS = 5_000
MAX_SEED_ASSETS = 500


# --- Commands ---------------------------------------------------------------


class EvidenceSeed(BaseModel):
    """The raw evidence the backend collected for an investigation.

    ``source_failures`` is part of the seed rather than an error: a source that
    could not be read is a coverage gap the analysis must state, not a reason to
    refuse the investigation (invariant #6).
    """

    raw_records: list[RawLogRecord] = Field(default_factory=list, max_length=MAX_SEED_RECORDS)
    requested_sources: list[str] = Field(default_factory=list)
    source_failures: list[dict[str, Any]] = Field(default_factory=list)
    time_window: TimeWindow | None = None


class CreateInvestigationRequest(BaseModel):
    """Trigger an investigation over collected evidence."""

    title: str | None = Field(default=None, max_length=512)
    trigger_source: TriggerSource = TriggerSource.ANALYST
    evidence: EvidenceSeed = Field(default_factory=EvidenceSeed)
    assets: list[AssetContext] = Field(default_factory=list, max_length=MAX_SEED_ASSETS)
    critical_assets: list[str] = Field(default_factory=list)
    internal_networks: list[str] = Field(default_factory=list)


class GateDecisionRequest(BaseModel):
    """A human decision at the approval gate (invariant #1)."""

    decision: DecisionType
    rationale: str | None = Field(default=None, max_length=4_000)
    # Where a redirect should resume from. Free text rather than a node name: the
    # analyst says what they want re-examined; the graph decides where that is.
    target: str | None = Field(default=None, max_length=255)


class RecommendationDecisionRequest(BaseModel):
    """A human decision on one remediation recommendation."""

    decision: ApprovalStatus
    rationale: str | None = Field(default=None, max_length=4_000)

    @field_validator("decision")
    @classmethod
    def _must_be_a_decision(cls, value: ApprovalStatus) -> ApprovalStatus:
        """``PENDING`` is the absence of a decision, so it cannot be submitted as one."""
        if value is ApprovalStatus.PENDING:
            raise ValueError("'pending' is not a decision a human can record")
        return value


# --- Read projections -------------------------------------------------------


class PipelineStage(BaseModel):
    """One agent stage and whether its artifact exists yet.

    Progress is reported from persisted artifacts rather than from the graph's
    in-memory position, so the answer is the same after a restart, and so a stage
    can never read "complete" on a screen while its output is absent from the
    record. ``skipped`` distinguishes work that was correctly not done — CVE
    research on a benign verdict — from work still outstanding.
    """

    name: str
    label: str
    complete: bool
    skipped: bool = False
    detail: str | None = None


class InvestigationSummary(BaseModel):
    """A row in the dashboard queue."""

    id: UUID
    title: str | None
    status: InvestigationStatus
    severity: Severity | None
    trigger_source: TriggerSource
    verdict: Verdict | None = None
    triage_priority: TriagePriority | None = None
    confidence: float | None = None
    pending_approvals: int = 0
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None


class InvestigationPage(BaseModel):
    """A page of investigations plus enough context to paginate honestly."""

    items: list[InvestigationSummary]
    total: int
    limit: int
    offset: int


class InvestigationSnapshot(BaseModel):
    """The live control view of one investigation — what the stream emits.

    Every event on the stream is a whole snapshot rather than a delta. A client
    that missed messages therefore needs no replay log to catch up: the next
    message it receives is the complete truth. That is what makes reconnection a
    non-event instead of a reconciliation problem.
    """

    id: UUID
    status: InvestigationStatus
    severity: Severity | None
    verdict: Verdict | None = None
    triage_priority: TriagePriority | None = None
    confidence: float | None = None
    awaiting_human: bool = False
    pipeline: list[PipelineStage] = Field(default_factory=list)
    event_count: int = 0
    cve_count: int = 0
    recommendation_count: int = 0
    pending_approvals: int = 0
    report_version: int = 0
    updated_at: datetime


class InvestigationDetail(BaseModel):
    """The investigation workspace header."""

    id: UUID
    title: str | None
    summary: str | None
    status: InvestigationStatus
    severity: Severity | None
    trigger_source: TriggerSource
    owner_id: UUID | None
    snapshot: InvestigationSnapshot
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None


class TimelineEvent(BaseModel):
    """One correlated event, with the provenance that makes it evidence.

    ``provenance`` is a free-form mapping because it records what the parser
    actually established about the record, which differs by source. It is
    presented, never interpreted, by the client.
    """

    id: UUID
    event_time: datetime
    source: str
    event_type: str
    actor: str | None
    notability: float
    raw_ref: str | None
    provenance: dict[str, Any] = Field(default_factory=dict)


class TimelineResponse(BaseModel):
    """An investigation's chronological reconstruction."""

    investigation_id: UUID
    events: list[TimelineEvent]
    truncated: bool = False


class ThreatIndicator(BaseModel):
    """An IoC as stored: raw value, inert rendering, and enrichment state.

    ``enriched`` is the field that matters. An indicator nothing asserted a
    reputation for is *unchecked*, not clean, and the UI must be able to say so.
    """

    type: str
    value: str
    defanged: str | None = None
    reputation: str | None = None
    source: str | None = None
    enriched: bool = False
    internal: bool = False
    observation_count: int = 0


class ThreatTechnique(BaseModel):
    """A mapped ATT&CK technique with its reasoning and citations."""

    technique_id: str
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    rationale: str | None = None
    confidence: float | None = None
    citations: list[Citation] = Field(default_factory=list)


class ThreatAssessmentView(BaseModel):
    """The Threat Detector's verdict as persisted."""

    id: UUID
    investigation_id: UUID
    verdict: Verdict
    severity: Severity
    triage_priority: TriagePriority
    enrichment_status: EnrichmentStatus
    confidence: float
    rationale: str | None
    indicators: list[ThreatIndicator] = Field(default_factory=list)
    techniques: list[ThreatTechnique] = Field(default_factory=list)
    version: int
    created_at: datetime


class CveFindingView(BaseModel):
    """One CVE from the dossier, confirmations and candidates alike."""

    id: UUID
    cve_id: str
    applicability: CveApplicability
    summary: str | None
    cvss: dict[str, Any] | None = None
    exploit_mapping: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    source_freshness: datetime | None = None
    version: int


class CveFindingsResponse(BaseModel):
    """An investigation's current dossier generation.

    ``researched`` separates "no vulnerabilities found" from "vulnerability
    research never ran", which are different statements about an estate.
    """

    investigation_id: UUID
    researched: bool
    findings: list[CveFindingView]
    version: int


class ReportView(BaseModel):
    """A generated incident report.

    The bodies are Markdown text and are transported as text. Nothing server-side
    turns them into markup, and the client is expected to render them as text —
    the report quotes untrusted log content, and the moment it becomes HTML that
    content becomes executable.
    """

    id: UUID
    investigation_id: UUID
    executive_summary: str
    technical_body: str
    citations: list[Citation] = Field(default_factory=list)
    status: ReportStatus
    version: int
    created_at: datetime


class ReportVersionRef(BaseModel):
    """One entry in a report's version history."""

    id: UUID
    version: int
    status: ReportStatus
    created_at: datetime


class ReportHistoryResponse(BaseModel):
    """Every generation of an investigation's report, oldest first."""

    investigation_id: UUID
    versions: list[ReportVersionRef]


class RecommendationView(BaseModel):
    """A remediation recommendation awaiting, or carrying, a human decision.

    There is no field here a client could read an executable out of, for the same
    reason there is none on the stored row: the shape itself is the guarantee.
    """

    id: UUID
    investigation_id: UUID
    action: str
    type: RecommendationType
    priority: TriagePriority
    rationale: str
    expected_impact: str | None
    citations: list[Citation] = Field(default_factory=list)
    approval_status: ApprovalStatus
    requires_human_approval: bool
    version: int
    created_at: datetime


class RecommendationsResponse(BaseModel):
    """The current remediation plan generation."""

    investigation_id: UUID
    recommendations: list[RecommendationView]
    version: int


class PendingApproval(BaseModel):
    """One item awaiting a human decision, with what the human needs to weigh."""

    kind: str
    id: UUID
    investigation_id: UUID
    title: str
    priority: TriagePriority | None = None
    confidence: float | None = None
    rationale: str | None = None


class PendingApprovalsResponse(BaseModel):
    """Everything outstanding on one investigation.

    ``gate_open`` is separate from the item list: an investigation can be waiting
    at the approval gate with an empty remediation plan, and a screen that showed
    only items would render that as "nothing to do".
    """

    investigation_id: UUID
    gate_open: bool
    items: list[PendingApproval]


class GateDecisionResponse(BaseModel):
    """The outcome of a recorded gate decision."""

    investigation_id: UUID
    decision: DecisionType
    status: InvestigationStatus
    awaiting_human: bool
    recorded_at: datetime
    # Stated explicitly on every decision response: approving authorizes work,
    # it does not perform it (invariant #2).
    executed: bool = False
    # Whether an outbound alert was queued as a result of this decision. Queued,
    # not delivered: dispatch runs behind the response, and whether a message
    # landed is a separate fact with its own record and its own screen.
    notification_queued: bool = False

"""Contracts for incident reporting (EDS §4.5, SAD §2.4).

The shapes flowing through the Incident Reporter: every upstream finding in, one
defensible document out.

A report is the artifact that outlives the investigation. It is what a regulator
reads, what the next analyst inherits, and what someone is held to a year later —
so the contracts here are built around a single rule from EDS §4.5:

    **Only claims supported by upstream state. No new findings.**

That is enforced structurally. Every :class:`ReportFinding` must carry
:class:`FindingSupport` naming the upstream artifacts it rests on — events,
signals, techniques, or CVEs — and a validator refuses a finding with no support
at all. A synthesis layer is exactly where invented detail creeps in, because
prose is fluent in a way structured output is not; requiring each sentence to
point at something makes the invention impossible rather than merely discouraged.

The second rule is that **gaps are marked, never omitted** (SAD §2.4 failure
handling). A missing upstream section produces a :class:`ReportCaveat`, so a
report assembled from partial evidence reads as partial. A report that quietly
drops the section it could not build is worse than no report: it looks complete.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from models.base import DomainModel
from models.enums import ReportStatus, Severity, Verdict
from models.values import Citation


class ReportSectionKind(StrEnum):
    """The upstream stage a finding or caveat belongs to.

    Sections mirror the pipeline, so a reader can tell at a glance which agent
    contributed what — and which agent had nothing to contribute.
    """

    EVIDENCE = "evidence"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    OVERALL = "overall"


class CaveatKind(StrEnum):
    """Why part of the report is weaker than it looks.

    Each value names a *specific* limitation rather than a general disclaimer.
    "Confidence may vary" tells a reader nothing; "the SIEM was unreachable for
    this window" tells them what to go and get.
    """

    MISSING_SECTION = "missing_section"
    COVERAGE_GAP = "coverage_gap"
    TIMELINE_TRUNCATED = "timeline_truncated"
    LOW_CONFIDENCE = "low_confidence"
    DEGRADED_ENRICHMENT = "degraded_enrichment"
    STALE_RESEARCH = "stale_research"
    UNCONFIRMED_APPLICABILITY = "unconfirmed_applicability"
    ESCALATION_REQUIRED = "escalation_required"


class FindingSupport(DomainModel):
    """The upstream artifacts a report claim rests on.

    Identifiers rather than prose, so support can be *checked* — a reader can
    follow ``event_ids`` back to the log lines and see for themselves.
    """

    event_ids: list[str] = Field(default_factory=list)
    signal_rule_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    indicator_values: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Whether nothing upstream backs this claim."""
        return not (
            self.event_ids
            or self.signal_rule_ids
            or self.technique_ids
            or self.cve_ids
            or self.indicator_values
        )


class ReportFinding(DomainModel):
    """One documented finding, with the evidence that supports it."""

    section: ReportSectionKind
    title: str
    detail: str
    support: FindingSupport
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    citations: list[Citation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _every_finding_is_supported(self) -> ReportFinding:
        """Refuse a finding that points at nothing.

        This is the anti-fabrication rule as a type. A reporter that can emit an
        unsupported claim will eventually emit one, and the resulting sentence is
        indistinguishable from a real finding by the time a human reads it.
        """
        if self.support.is_empty:
            raise ValueError(
                f"report finding {self.title!r} cites no upstream support; "
                "a report may only restate findings the investigation produced"
            )
        return self


class ReportCaveat(DomainModel):
    """A stated limitation on the report's reliability."""

    kind: CaveatKind
    section: ReportSectionKind
    detail: str


class AffectedAsset(DomainModel):
    """One asset the investigation touched, and what is known about it."""

    hostname: str
    event_count: int = Field(default=0, ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confirmed_cve_ids: list[str] = Field(default_factory=list)
    # Set when the asset was designated business-critical for this investigation.
    critical: bool = False


class ReportTimelineEntry(DomainModel):
    """One ordered step in the narrative, traceable to its source event.

    ``raw_ref`` points at the original log line. A timeline a reader cannot walk
    back to the raw evidence is a story rather than a record, and the report has
    to survive someone disagreeing with it.
    """

    event_id: str
    occurred_at: datetime
    source_id: str
    summary: str
    notability: float = 0.0
    raw_ref: str | None = None


class IncidentReportRequest(DomainModel):
    """Input to the Incident Reporter (EDS §4.5 input schema).

    All three upstream sections are optional, and that is deliberate: an
    investigation can reach the reporter having skipped CVE research (a benign
    verdict) or having produced nothing at all. A missing section becomes a
    caveat, so the contract must be able to represent its absence.
    """

    investigation_id: str
    title: str | None = None
    trigger_source: str | None = None
    opened_at: datetime | None = None
    log_analysis: dict[str, object] | None = None
    threat_assessment: dict[str, object] | None = None
    vulnerability_dossier: dict[str, object] | None = None
    critical_assets: list[str] = Field(default_factory=list)
    # How many timeline entries the narrative carries before it summarizes the
    # remainder by reference.
    max_timeline_entries: int = Field(default=50, ge=1)


class IncidentReport(DomainModel):
    """Output of the Incident Reporter (EDS §4.5 output schema).

    ``version`` and ``generated_from`` together make the report reproducible: it
    states which schema version of the investigation state produced it, so a
    regenerated report can be compared against the one an analyst actually read.
    """

    investigation_id: str
    title: str
    status: ReportStatus = ReportStatus.DRAFT
    executive_summary: str = ""
    technical_body: str = ""
    verdict: Verdict | None = None
    severity: Severity | None = None
    timeline: list[ReportTimelineEntry] = Field(default_factory=list)
    findings: list[ReportFinding] = Field(default_factory=list)
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    indicators: list[dict[str, object]] = Field(default_factory=list)
    techniques: list[dict[str, object]] = Field(default_factory=list)
    cves: list[dict[str, object]] = Field(default_factory=list)
    caveats: list[ReportCaveat] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    version: int = Field(default=1, ge=1)
    # Which upstream sections were actually available, so an incomplete report
    # can say what it was built from rather than only what it lacks.
    generated_from: list[ReportSectionKind] = Field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Whether every upstream section contributed to this report."""
        return not any(caveat.kind is CaveatKind.MISSING_SECTION for caveat in self.caveats)

    def findings_in(self, section: ReportSectionKind) -> list[ReportFinding]:
        """The findings contributed by one pipeline stage."""
        return [finding for finding in self.findings if finding.section is section]

"""The Incident Reporter agent (EDS §4.5, SAD §2.4).

The last agent before a human reads anything. It takes what the Log Analyzer,
Threat Detector, and CVE Research produced and assembles one document for two
audiences at once — an executive summary and a technical body — without adding a
single claim of its own.

That constraint is the whole design. Synthesis is where fabrication happens,
because prose is fluent in a way structured output is not: a sentence that
smooths over a gap reads better than one that names it, and the smoother sentence
is the one that survives review. So this agent never composes free-form findings.
Every finding is a **restatement of a specific upstream artifact**, carrying the
identifiers it rests on, and the contract refuses a finding with no support at
all.

The second rule is that gaps are marked rather than omitted (SAD §2.4). A missing
section, a truncated timeline, degraded enrichment, stale research, an unconfirmed
CVE — each becomes a stated caveat. One distinction matters here: CVE research
that was *correctly skipped* because the verdict was benign is not a gap, and
reporting it as one would make every routine investigation read as incomplete.
The reporter therefore distinguishes a section that is missing from one that was
never expected.

Like the agents before it, the pipeline is deterministic: assemble, restate,
caveat, render. A report has to be regenerable from state and identical when
regenerated, or "regenerate from the investigation" is not a recovery path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agents.shared.contracts import AgentDegradation, AgentOutcome
from config.logging import get_logger
from models.enums import ReportStatus, Verdict
from models.logs import NormalizedEvent, TimelineEntry
from models.report import (
    CaveatKind,
    FindingSupport,
    IncidentReport,
    ReportCaveat,
    ReportFinding,
    ReportSectionKind,
)
from models.threat import ThreatDetectionResult
from models.vulnerability import CveResearchResult
from prompts.assembly import INCIDENT_REPORTER_PROMPT
from tools.rendering import render_executive_summary, render_technical_body
from tools.reporting import assemble_timeline, collect_affected_assets, compile_citations

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.report import IncidentReportRequest
    from models.values import Citation

_logger = get_logger(__name__)

AGENT_NAME = "incident_reporter"

# Tools this agent is allow-listed to use (EDS §3.7 least privilege).
ALLOWED_TOOLS = (
    "assemble_timeline",
    "collect_affected_assets",
    "compile_citations",
    "render_report",
)

# Below this, an upstream section's confidence is called out in the report rather
# than left for a reader to notice in a percentage.
LOW_CONFIDENCE_THRESHOLD = 0.6


class IncidentReporter:
    """Synthesizes the investigation into one defensible report."""

    def __init__(self, *, low_confidence_threshold: float = LOW_CONFIDENCE_THRESHOLD) -> None:
        self._low_confidence = low_confidence_threshold

    def report(self, request: IncidentReportRequest) -> AgentOutcome[IncidentReport]:
        """Assemble the report, stating everything it could not build."""
        degradations: list[AgentDegradation] = []
        caveats: list[ReportCaveat] = []

        events, entries, coverage_gaps = _read_log_analysis(request.log_analysis)
        threat = _read_model(ThreatDetectionResult, request.threat_assessment)
        dossier = _read_model(CveResearchResult, request.vulnerability_dossier)

        sections = _sections_present(request, threat, dossier)
        expected = _sections_expected(threat)
        caveats.extend(_missing_section_caveats(expected - sections))
        degradations.extend(
            AgentDegradation(reason="missing_section", detail=item.value)
            for item in sorted(expected - sections, key=lambda kind: kind.value)
        )

        timeline, omitted = assemble_timeline(
            entries, limit=request.max_timeline_entries, events=events
        )
        if omitted:
            caveats.append(
                ReportCaveat(
                    kind=CaveatKind.TIMELINE_TRUNCATED,
                    section=ReportSectionKind.EVIDENCE,
                    detail=(
                        f"{omitted} of {omitted + len(timeline)} timeline entries were omitted; "
                        "the most notable were retained and the full sequence remains in "
                        "the investigation record"
                    ),
                )
            )

        caveats.extend(_evidence_caveats(coverage_gaps))
        caveats.extend(self._threat_caveats(threat))
        caveats.extend(self._vulnerability_caveats(dossier))

        findings = [
            *_evidence_findings(events, entries),
            *_threat_findings(threat),
            *_vulnerability_findings(dossier),
        ]
        confidence = self._confidence(threat, dossier, expected=expected, present=sections)

        report = IncidentReport(
            investigation_id=request.investigation_id,
            title=request.title or f"Incident report — investigation {request.investigation_id}",
            status=ReportStatus.DRAFT,
            verdict=threat.verdict if threat else None,
            severity=threat.severity.level if threat else None,
            timeline=timeline,
            findings=findings,
            affected_assets=collect_affected_assets(
                events,
                confirmed=dossier.cves if dossier else (),
                critical_assets=request.critical_assets,
            ),
            indicators=_indicator_rows(threat),
            techniques=_technique_rows(threat),
            cves=_cve_rows(dossier),
            caveats=caveats,
            citations=compile_citations(*_citation_groups(threat, dossier)),
            confidence=confidence,
            generated_from=sorted(sections, key=lambda kind: kind.value),
        )
        report = report.model_copy(
            update={
                "executive_summary": render_executive_summary(report),
                "technical_body": render_technical_body(report),
            }
        )

        _logger.info(
            "incident_report_complete",
            investigation_id=request.investigation_id,
            findings=len(report.findings),
            timeline_entries=len(report.timeline),
            caveats=len(report.caveats),
            citations=len(report.citations),
            complete=report.is_complete,
            confidence=confidence,
        )

        return AgentOutcome(
            agent=AGENT_NAME,
            output=report,
            confidence=confidence,
            prompt_version=INCIDENT_REPORTER_PROMPT.version,
            tool_calls=[
                {"tool": "assemble_timeline", "count": len(report.timeline)},
                {"tool": "collect_affected_assets", "count": len(report.affected_assets)},
                {"tool": "compile_citations", "count": len(report.citations)},
                {"tool": "render_report", "count": 1},
            ],
            degradations=degradations,
        )

    # --- Caveats ----------------------------------------------------------

    def _threat_caveats(self, threat: ThreatDetectionResult | None) -> list[ReportCaveat]:
        """Everything about the assessment a reader should weigh it against."""
        if threat is None:
            return []

        caveats: list[ReportCaveat] = []
        if threat.confidence < self._low_confidence:
            caveats.append(
                ReportCaveat(
                    kind=CaveatKind.LOW_CONFIDENCE,
                    section=ReportSectionKind.THREAT,
                    detail=(
                        f"the threat assessment was reached with {threat.confidence:.0%} "
                        "confidence; treat the verdict as provisional"
                    ),
                )
            )
        if threat.enrichment_status.value != "complete":
            caveats.append(
                ReportCaveat(
                    kind=CaveatKind.DEGRADED_ENRICHMENT,
                    section=ReportSectionKind.THREAT,
                    detail=(
                        f"indicator reputation was {threat.enrichment_status.value}; "
                        "indicators without a named source are unchecked, not clean"
                    ),
                )
            )
        if threat.escalation_required and threat.escalation_reason:
            caveats.append(
                ReportCaveat(
                    kind=CaveatKind.ESCALATION_REQUIRED,
                    section=ReportSectionKind.THREAT,
                    detail=threat.escalation_reason,
                )
            )
        return caveats

    @staticmethod
    def _vulnerability_caveats(dossier: CveResearchResult | None) -> list[ReportCaveat]:
        if dossier is None:
            return []

        caveats: list[ReportCaveat] = []
        if dossier.stale:
            caveats.append(
                ReportCaveat(
                    kind=CaveatKind.STALE_RESEARCH,
                    section=ReportSectionKind.VULNERABILITY,
                    detail=(
                        "vulnerability research did not rest on the live feed; some or all "
                        "records came from the indexed corpus and may be out of date"
                    ),
                )
            )
        if dossier.candidates:
            caveats.append(
                ReportCaveat(
                    kind=CaveatKind.UNCONFIRMED_APPLICABILITY,
                    section=ReportSectionKind.VULNERABILITY,
                    detail=(
                        f"{len(dossier.candidates)} vulnerability candidate(s) could not be "
                        "confirmed against the asset inventory and require manual checking"
                    ),
                )
            )
        return caveats

    def _confidence(
        self,
        threat: ThreatDetectionResult | None,
        dossier: CveResearchResult | None,
        *,
        expected: set[ReportSectionKind],
        present: set[ReportSectionKind],
    ) -> float:
        """Inherited from upstream, scaled by how much of the report exists.

        Completeness is measured against the sections that *should* have run, not
        against all three — CVE research correctly skipped on a benign verdict is
        not a shortfall, and counting it as one would make every routine
        investigation report look doubtful.
        """
        upstream = [item.confidence for item in (threat, dossier) if item is not None]
        if not upstream or not expected:
            return 0.0
        completeness = len(present & expected) / len(expected)
        return round(min(1.0, max(0.0, sum(upstream) / len(upstream) * completeness)), 4)


# --- Reading upstream state -------------------------------------------------


def _read_log_analysis(
    payload: dict[str, object] | None,
) -> tuple[list[NormalizedEvent], list[TimelineEntry], list[str]]:
    """Read the evidence section, tolerating anything malformed inside it.

    One unreadable event must not cost the report; it simply does not appear,
    and the section as a whole is still counted as present.
    """
    data: dict[str, Any] = dict(payload or {})
    events = _validate_each(NormalizedEvent, data.get("events"))
    entries = _validate_each(TimelineEntry, data.get("timeline"))
    gaps = [str(item) for item in data.get("coverage_gaps", []) or [] if item]
    return events, entries, gaps


def _read_model(model: type[Any], payload: dict[str, object] | None) -> Any:
    """Validate a whole upstream section, or ``None`` if it is absent or unreadable."""
    if not payload:
        return None
    try:
        return model.model_validate(payload)
    except ValueError:
        _logger.warning("report_section_unreadable", section=model.__name__)
        return None


def _validate_each(model: type[Any], payload: object) -> list[Any]:
    if not isinstance(payload, list):
        return []
    validated: list[Any] = []
    for item in payload:
        try:
            validated.append(model.model_validate(item))
        except ValueError:
            continue
    return validated


def _sections_present(
    request: IncidentReportRequest,
    threat: ThreatDetectionResult | None,
    dossier: CveResearchResult | None,
) -> set[ReportSectionKind]:
    present: set[ReportSectionKind] = set()
    if request.log_analysis:
        present.add(ReportSectionKind.EVIDENCE)
    if threat is not None:
        present.add(ReportSectionKind.THREAT)
    if dossier is not None:
        present.add(ReportSectionKind.VULNERABILITY)
    return present


def _sections_expected(threat: ThreatDetectionResult | None) -> set[ReportSectionKind]:
    """Which sections this investigation ought to have produced.

    Vulnerability research is expected only when the verdict was not benign,
    because the graph deliberately skips it otherwise. A report must not fault an
    investigation for work the pipeline was right not to do.
    """
    expected = {ReportSectionKind.EVIDENCE, ReportSectionKind.THREAT}
    if threat is not None and threat.verdict is not Verdict.BENIGN:
        expected.add(ReportSectionKind.VULNERABILITY)
    return expected


def _missing_section_caveats(missing: set[ReportSectionKind]) -> list[ReportCaveat]:
    return [
        ReportCaveat(
            kind=CaveatKind.MISSING_SECTION,
            section=section,
            detail=(
                f"the {section.value} section is missing from this report; the upstream "
                "stage produced nothing readable, so the report is assembled without it"
            ),
        )
        for section in sorted(missing, key=lambda kind: kind.value)
    ]


def _evidence_caveats(coverage_gaps: Sequence[str]) -> list[ReportCaveat]:
    return [
        ReportCaveat(
            kind=CaveatKind.COVERAGE_GAP,
            section=ReportSectionKind.EVIDENCE,
            detail=gap,
        )
        for gap in coverage_gaps
    ]


# --- Findings ---------------------------------------------------------------


def _evidence_findings(
    events: Sequence[NormalizedEvent], entries: Sequence[TimelineEntry]
) -> list[ReportFinding]:
    """Restate what was observed, without characterizing it."""
    if not events:
        return []

    sources = sorted({event.source_id for event in events})
    hosts = sorted({event.host for event in events if event.host})
    return [
        ReportFinding(
            section=ReportSectionKind.EVIDENCE,
            title=f"{len(events)} security-relevant events normalized",
            detail=(
                f"Evidence was collected from {len(sources)} source(s) "
                f"({', '.join(sources)}) and normalized into {len(entries)} timeline "
                f"entries across {len(hosts) or 'no identified'} host(s)"
                + (f": {', '.join(hosts)}." if hosts else ".")
            ),
            support=FindingSupport(event_ids=[event.event_id for event in events]),
            confidence=round(sum(event.confidence for event in events) / len(events), 4),
        )
    ]


def _threat_findings(threat: ThreatDetectionResult | None) -> list[ReportFinding]:
    """One finding per detection that fired, plus each confirmed hostile indicator."""
    if threat is None:
        return []

    findings = [
        ReportFinding(
            section=ReportSectionKind.THREAT,
            title=signal.name,
            detail=f"{signal.description} Observed: {signal.detail}",
            support=FindingSupport(
                event_ids=list(signal.event_ids),
                signal_rule_ids=[signal.rule_id],
                technique_ids=list(signal.technique_ids),
            ),
            confidence=threat.confidence,
        )
        for signal in threat.signals
    ]

    findings.extend(
        ReportFinding(
            section=ReportSectionKind.THREAT,
            title=f"Indicator reported as {ioc.reputation.value}",
            detail=(
                f"{ioc.reputation_source} reported {ioc.defanged} as "
                f"{ioc.reputation.value} ({ioc.reputation_detail})."
            ),
            support=FindingSupport(event_ids=list(ioc.event_ids), indicator_values=[ioc.defanged]),
            confidence=threat.confidence,
        )
        for ioc in threat.hostile_iocs
    )
    return findings


def _vulnerability_findings(dossier: CveResearchResult | None) -> list[ReportFinding]:
    """One finding per confirmed CVE. Candidates are caveats, not findings."""
    if dossier is None:
        return []

    findings: list[ReportFinding] = []
    for assessment in dossier.cves:
        record = assessment.record
        score = f" CVSS {record.cvss.base_score}/10." if record.cvss else ""
        evidence = " ".join(item.detail for item in assessment.evidence if item.detail)
        findings.append(
            ReportFinding(
                section=ReportSectionKind.VULNERABILITY,
                title=f"{record.cve_id} confirmed applicable",
                detail=f"{record.summary}{score} {evidence}".strip(),
                support=FindingSupport(
                    cve_ids=[record.cve_id],
                    event_ids=list(assessment.exploit_mapping.event_ids),
                    technique_ids=list(assessment.exploit_mapping.technique_ids),
                ),
                confidence=assessment.confidence,
                citations=list(assessment.citations),
            )
        )
    return findings


# --- Structured tables ------------------------------------------------------


def _indicator_rows(threat: ThreatDetectionResult | None) -> list[dict[str, object]]:
    """Indicators in defanged form — a report must not carry a live link."""
    if threat is None:
        return []
    return [
        {
            "type": ioc.type.value,
            "value": ioc.value,
            "defanged": ioc.defanged,
            "reputation": ioc.reputation.value,
            "source": ioc.reputation_source,
            "internal": ioc.internal,
        }
        for ioc in threat.iocs
    ]


def _technique_rows(threat: ThreatDetectionResult | None) -> list[dict[str, object]]:
    if threat is None:
        return []
    return [
        {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactics": list(technique.tactics),
            "rationale": technique.rationale,
            "confidence": technique.confidence,
        }
        for technique in threat.attack_techniques
    ]


def _cve_rows(dossier: CveResearchResult | None) -> list[dict[str, object]]:
    """Only confirmed CVEs reach the vulnerabilities table.

    Candidates are surfaced as a caveat instead: listing them beside confirmed
    findings invites a reader to treat "might apply" as "applies".
    """
    if dossier is None:
        return []
    return [
        {
            "cve_id": assessment.cve_id,
            "cvss_score": (assessment.record.cvss.base_score if assessment.record.cvss else None),
            "severity": (assessment.record.cvss.severity.value if assessment.record.cvss else None),
            "applicability": assessment.applicability.value,
            "summary": assessment.record.summary,
        }
        for assessment in dossier.cves
    ]


def _citation_groups(
    threat: ThreatDetectionResult | None, dossier: CveResearchResult | None
) -> list[list[Citation]]:
    groups: list[list[Citation]] = []
    if threat is not None:
        groups.append(list(threat.citations))
    if dossier is not None:
        groups.append(
            [
                citation
                for assessment in dossier.all_assessments
                for citation in assessment.citations
            ]
        )
    return groups

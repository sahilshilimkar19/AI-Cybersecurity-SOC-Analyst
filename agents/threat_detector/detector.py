"""The Threat Detector agent (EDS §4.3, SAD §2.2).

The Log Analyzer establishes *what happened*. This agent decides *what it means*:
a verdict, the indicators worth pivoting on, the ATT&CK techniques the activity
resembles, a severity, and a triage priority — plus, explicitly, how sure it is
and what it could not check.

Its whole design turns on one distinction. A detector that blurs *observed* into
*concluded* produces confident-sounding output that cannot be audited, and the
first time it is wrong nobody can tell where it went wrong. So every statement it
makes is emitted as a labelled claim, every signal points back at the events that
fired it, and every technique carries a citation to its ATT&CK page.

The second load-bearing rule is that **reputation is never invented**. Enrichment
is a call to somebody else's opinion; when it is unavailable the indicators stay
``UNKNOWN``, the assessment is flagged degraded, and confidence drops. There is no
path by which "we did not check" becomes "it is clean" (SAD §2.2).

Like the Log Analyzer, the pipeline is deterministic — extract, enrich, detect,
map, score. That is what makes the labelled fixtures in the test suite meaningful
as calibration rather than as snapshots, and what lets an assessment be
reproduced exactly when someone disputes it. The model-assisted pass arrives with
the AI layer and inherits this contract unchanged.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from agents.shared.contracts import AgentDegradation, AgentOutcome
from config.logging import get_logger
from integrations.threat_intel import UnavailableReputationProvider, enrich_indicators
from models.enums import EnrichmentStatus
from models.logs import NormalizedEvent
from models.threat import AssessmentClaim, ClaimKind, ThreatDetectionResult
from models.values import Citation
from prompts.assembly import THREAT_DETECTOR_PROMPT
from tools.attack import map_techniques
from tools.detection import DetectionContext, evaluate_rules, signal_from_hostile_indicators
from tools.iocs import extract_iocs
from tools.severity import (
    assess_escalation,
    corroborating_rules,
    derive_priority,
    derive_verdict,
    score_severity,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from integrations.threat_intel import ReputationProvider
    from memory.knowledge import KnowledgeMemory
    from models.enums import Verdict
    from models.threat import (
        DetectionSignal,
        IocIndicator,
        SeverityAssessment,
        TechniqueMapping,
        ThreatDetectionRequest,
    )

_logger = get_logger(__name__)

AGENT_NAME = "threat_detector"

# Tools this agent is allow-listed to use (EDS §3.7 least privilege).
ALLOWED_TOOLS = (
    "extract_iocs",
    "evaluate_rules",
    "map_techniques",
    "score_severity",
    "lookup_reputation",
    "retrieve_knowledge",
)

# How far apart related activity can be and still count as one episode.
DEFAULT_DETECTION_WINDOW = timedelta(minutes=30)

# Chunks of detection knowledge retrieved to ground the assessment.
_KNOWLEDGE_LIMIT = 4

# Confidence multipliers per enrichment outcome. Unavailable enrichment is a real
# blind spot, not a formality, so it costs more than a partial failure.
_ENRICHMENT_CONFIDENCE: dict[EnrichmentStatus, float] = {
    EnrichmentStatus.COMPLETE: 1.0,
    EnrichmentStatus.DEGRADED: 0.85,
    EnrichmentStatus.UNAVAILABLE: 0.7,
}

# Each coverage gap costs this much confidence, down to the floor. Gaps never
# reduce severity — see tools/severity.py.
_GAP_PENALTY = 0.1
_GAP_PENALTY_FLOOR = 0.6


class ThreatDetector:
    """Assesses normalized evidence into a threat verdict."""

    def __init__(
        self,
        *,
        reputation: ReputationProvider | None = None,
        knowledge: KnowledgeMemory | None = None,
        detection_window: timedelta = DEFAULT_DETECTION_WINDOW,
        max_indicators: int = 25,
    ) -> None:
        self._reputation = reputation or UnavailableReputationProvider()
        self._knowledge = knowledge
        self._window = detection_window
        self._max_indicators = max_indicators

    def assess(self, request: ThreatDetectionRequest) -> AgentOutcome[ThreatDetectionResult]:
        """Assess an investigation's evidence, reporting everything it could not check."""
        degradations: list[AgentDegradation] = []
        events, unreadable = _parse_events(request.events)
        if unreadable:
            degradations.append(
                AgentDegradation(
                    reason="unreadable_events",
                    detail=f"{unreadable} event(s) did not match the normalized contract",
                )
            )

        internal = tuple(request.internal_networks)
        iocs = extract_iocs(events, internal_networks=internal)
        iocs, enrichment_status, enrichment_notes = enrich_indicators(
            iocs, self._reputation, limit=self._max_indicators
        )
        for note in enrichment_notes:
            degradations.append(AgentDegradation(reason="enrichment", detail=note))

        signals = evaluate_rules(
            DetectionContext(events=events, window=self._window, internal_networks=internal)
        )
        hostile = signal_from_hostile_indicators(iocs)
        if hostile is not None:
            signals = sorted([*signals, hostile], key=lambda item: (-item.weight, item.rule_id))

        techniques = map_techniques(signals)
        citations, grounded = self._ground(techniques, signals)
        if self._knowledge is not None and not grounded:
            degradations.append(
                AgentDegradation(
                    reason="knowledge_unavailable",
                    detail="no detection knowledge was retrieved to ground the assessment",
                )
            )

        critical = _critical_assets_involved(events, request.critical_assets)
        severity = score_severity(signals, critical_assets_involved=critical)
        verdict = derive_verdict(severity, signals, iocs)
        confidence = self._confidence(
            events=events,
            signals=signals,
            enrichment_status=enrichment_status,
            coverage_gaps=request.coverage_gaps,
        )
        priority = derive_priority(verdict, severity, critical_asset_involved=bool(critical))
        escalate, escalation_reason = assess_escalation(
            verdict,
            severity,
            confidence=confidence,
            critical_asset_involved=bool(critical),
            coverage_gaps=request.coverage_gaps,
        )

        result = ThreatDetectionResult(
            investigation_id=request.investigation_id,
            verdict=verdict,
            severity=severity,
            triage_priority=priority,
            iocs=iocs,
            attack_techniques=techniques,
            signals=signals,
            claims=_build_claims(signals, iocs, techniques, verdict, severity, enrichment_status),
            enrichment_status=enrichment_status,
            escalation_required=escalate,
            escalation_reason=escalation_reason,
            knowledge_grounded=grounded,
            citations=citations,
            confidence=confidence,
        )

        _logger.info(
            "threat_assessment_complete",
            investigation_id=request.investigation_id,
            verdict=verdict.value,
            severity=severity.level.value,
            score=severity.score,
            signals=len(signals),
            iocs=len(iocs),
            techniques=len(techniques),
            enrichment_status=enrichment_status.value,
            escalation_required=escalate,
            confidence=confidence,
        )

        return AgentOutcome(
            agent=AGENT_NAME,
            output=result,
            confidence=confidence,
            prompt_version=THREAT_DETECTOR_PROMPT.version,
            tool_calls=[
                {"tool": "extract_iocs", "count": len(iocs)},
                {"tool": "evaluate_rules", "count": len(signals)},
                {"tool": "map_techniques", "count": len(techniques)},
                {"tool": "lookup_reputation", "count": sum(1 for ioc in iocs if ioc.enriched)},
                {"tool": "retrieve_knowledge", "count": len(citations)},
            ],
            degradations=degradations,
        )

    # --- Internals --------------------------------------------------------

    def _ground(
        self, techniques: Sequence[TechniqueMapping], signals: Sequence[DetectionSignal]
    ) -> tuple[list[Citation], bool]:
        """Collect the references supporting the assessment.

        Catalogue citations are always available — a mapped technique is only ever
        emitted with its ATT&CK page attached. Retrieved detection knowledge is
        additive: when the corpus is unreachable the assessment is still cited,
        just less richly, and ``knowledge_grounded`` records the difference.
        """
        citations: list[Citation] = [
            citation for technique in techniques for citation in technique.citations
        ]
        if self._knowledge is None or not self._knowledge.is_available or not signals:
            return _dedupe_citations(citations), False

        query = _knowledge_query(techniques, signals)
        chunks = self._knowledge.search(query, limit=_KNOWLEDGE_LIMIT)
        citations.extend(
            Citation(
                # The knowledge tier identifies a passage by its chunk id; the
                # source name doubles as the source identifier at this level.
                source_id=chunk.source,
                source=chunk.source,
                chunk_id=chunk.chunk_id,
            )
            for chunk in chunks
        )
        return _dedupe_citations(citations), bool(chunks)

    @staticmethod
    def _confidence(
        *,
        events: Sequence[NormalizedEvent],
        signals: Sequence[DetectionSignal],
        enrichment_status: EnrichmentStatus,
        coverage_gaps: Sequence[str],
    ) -> float:
        """Calibrate confidence from evidence quality, corroboration, and blind spots.

        Four factors, each of which can only lower the result:

        * how cleanly the underlying records parsed (garbage in, uncertain out);
        * how many independent rules agree — with a deliberately moderate prior
          for the "nothing fired" case, because absence of evidence in a partial
          log set is weaker than it looks;
        * whether reputation could be checked at all;
        * how much of the evidence picture was missing.
        """
        if not events:
            return 0.0

        parse_quality = sum(event.confidence for event in events) / len(events)

        corroborating = corroborating_rules(signals)
        if not signals:
            # Nothing fired. Confident, but not certain: a quiet log set is weak
            # evidence of quiet, since what an attacker removed also looks quiet.
            corroboration = 0.8
        elif not corroborating:
            corroboration = 0.5
        else:
            corroboration = min(1.0, 0.5 + 0.25 * (len(corroborating) - 1))

        enrichment_factor = _ENRICHMENT_CONFIDENCE.get(enrichment_status, 0.7)
        gap_factor = max(_GAP_PENALTY_FLOOR, 1.0 - _GAP_PENALTY * len(coverage_gaps))

        score = parse_quality * corroboration * enrichment_factor * gap_factor
        return round(min(1.0, max(0.0, score)), 4)


def _parse_events(payload: Sequence[dict[str, object]]) -> tuple[list[NormalizedEvent], int]:
    """Validate incoming events, counting rather than raising on malformed ones.

    A single malformed event must not cost the whole assessment; the count
    becomes a declared degradation so the shortfall is visible.
    """
    events: list[NormalizedEvent] = []
    unreadable = 0
    for item in payload:
        try:
            events.append(NormalizedEvent.model_validate(item))
        except ValueError:
            unreadable += 1
    return events, unreadable


def _critical_assets_involved(
    events: Sequence[NormalizedEvent], critical_assets: Sequence[str]
) -> list[str]:
    """Which designated critical assets appear in the evidence."""
    if not critical_assets:
        return []
    hosts = {event.host.lower() for event in events if event.host}
    return sorted({asset for asset in critical_assets if asset.lower() in hosts})


def _knowledge_query(
    techniques: Sequence[TechniqueMapping], signals: Sequence[DetectionSignal]
) -> str:
    """Build the retrieval query from what actually fired."""
    parts = [f"{technique.technique_id} {technique.name}" for technique in techniques[:3]]
    parts.extend(signal.name for signal in signals[:3])
    return "; ".join(parts) or "security detection guidance"


def _dedupe_citations(citations: Sequence[Citation]) -> list[Citation]:
    """Drop repeats, keeping first-seen order."""
    seen: set[tuple[str, str | None]] = set()
    unique: list[Citation] = []
    for citation in citations:
        key = (citation.source_id, citation.chunk_id or citation.url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(citation)
    return unique


def _build_claims(
    signals: Sequence[DetectionSignal],
    iocs: Sequence[IocIndicator],
    techniques: Sequence[TechniqueMapping],
    verdict: Verdict,
    severity: SeverityAssessment,
    enrichment_status: EnrichmentStatus,
) -> list[AssessmentClaim]:
    """Split what was seen from what was concluded (EDS §4.3 validation rule).

    Observations restate the evidence; inferences restate the judgement. Keeping
    them in one ordered list — rather than in two unrelated fields — means a
    reader sees the reasoning in the order it was made, with the label attached
    to each step.
    """
    claims: list[AssessmentClaim] = []

    for signal in signals:
        claims.append(
            AssessmentClaim(
                kind=ClaimKind.OBSERVATION,
                statement=f"{signal.name}: {signal.detail}",
                event_ids=list(signal.event_ids),
            )
        )

    for ioc in iocs:
        if not ioc.enriched:
            continue
        claims.append(
            AssessmentClaim(
                kind=ClaimKind.OBSERVATION,
                statement=(
                    f"{ioc.reputation_source} reported {ioc.defanged} as "
                    f"{ioc.reputation.value} ({ioc.reputation_detail})"
                ),
                event_ids=list(ioc.event_ids),
            )
        )

    if enrichment_status is not EnrichmentStatus.COMPLETE:
        claims.append(
            AssessmentClaim(
                kind=ClaimKind.OBSERVATION,
                statement=(
                    f"Indicator reputation was {enrichment_status.value}; indicators without a "
                    "named source remain unknown rather than assumed clean."
                ),
            )
        )

    for technique in techniques:
        claims.append(
            AssessmentClaim(
                kind=ClaimKind.INFERENCE,
                statement=(
                    f"The observed activity is consistent with {technique.technique_id} "
                    f"({technique.name}); {technique.rationale}"
                ),
                event_ids=list(technique.event_ids),
                citations=list(technique.citations),
            )
        )

    claims.append(
        AssessmentClaim(
            kind=ClaimKind.INFERENCE,
            statement=f"Verdict {verdict.value}: {severity.rationale}",
        )
    )
    return claims

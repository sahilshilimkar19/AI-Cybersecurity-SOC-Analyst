"""Persisting threat assessments (invariant #7).

The Threat Detector *produces* an assessment; the backend *writes* it. Keeping
the write here rather than inside the agent or the graph node preserves the
sole-write-boundary invariant and keeps agents free of database concerns — the
same split the evidence service makes.

Two things travel with every row and are the reason it is worth persisting at
all. First, the **rationale**: a verdict without its reasoning is an assertion,
and an assertion cannot be reviewed six weeks later when someone asks why the
incident was closed. Second, the **version**: assessments are superseded, never
edited, so the record shows what was believed at each point rather than only what
was believed last.

Indicators are stored **defanged** alongside their raw value, so anything that
renders them — a report, a UI, a Slack message — has an inert form available and
nobody has to remember to neutralize them at the edge.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.db.orm.analysis import ThreatAssessment
from backend.db.repositories.analysis import ThreatAssessmentRepository
from config.logging import get_logger

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.orm import Session

    from models.threat import ThreatDetectionResult

_logger = get_logger(__name__)


def to_threat_assessment(
    investigation_id: UUID, result: ThreatDetectionResult, *, version: int = 1
) -> ThreatAssessment:
    """Map an assessment result onto its persistent row."""
    return ThreatAssessment(
        investigation_id=investigation_id,
        verdict=result.verdict,
        severity=result.severity.level,
        triage_priority=result.triage_priority,
        enrichment_status=result.enrichment_status,
        confidence=result.confidence,
        rationale=_rationale(result),
        iocs=[
            {
                "type": ioc.type.value,
                "value": ioc.value,
                "defanged": ioc.defanged,
                "reputation": ioc.reputation.value,
                # Null when nothing asserted a reputation: the absence of a
                # source is what marks the value as unchecked rather than clean.
                "source": ioc.reputation_source,
                "enriched": ioc.enriched,
                "internal": ioc.internal,
                "observation_count": ioc.observation_count,
                "event_ids": ioc.event_ids,
            }
            for ioc in result.iocs
        ],
        attack_techniques=[
            {
                "technique_id": technique.technique_id,
                "name": technique.name,
                "tactics": technique.tactics,
                "rationale": technique.rationale,
                "confidence": technique.confidence,
                "event_ids": technique.event_ids,
                "citations": [citation.model_dump(mode="json") for citation in technique.citations],
            }
            for technique in result.attack_techniques
        ],
        version=version,
    )


def record_threat_assessment(
    session: Session, investigation_id: UUID, result: ThreatDetectionResult
) -> ThreatAssessment:
    """Persist an assessment as the next version for its investigation."""
    repository = ThreatAssessmentRepository(session)
    version = repository.latest_version(investigation_id) + 1
    row = repository.add(to_threat_assessment(investigation_id, result, version=version))

    _logger.info(
        "threat_assessment_recorded",
        investigation_id=str(investigation_id),
        version=version,
        verdict=result.verdict.value,
        severity=result.severity.level.value,
        escalation_required=result.escalation_required,
    )
    return row


def _rationale(result: ThreatDetectionResult) -> str:
    """The stored explanation: the severity reasoning plus any escalation note.

    Escalation is appended rather than kept in a separate column because the
    reason a case needed a senior human *is* part of why the verdict reads as it
    does, and splitting them invites showing one without the other.
    """
    parts = [result.severity.rationale]
    if result.escalation_required and result.escalation_reason:
        parts.append(f"Escalation required: {result.escalation_reason}")
    return " ".join(part for part in parts if part)

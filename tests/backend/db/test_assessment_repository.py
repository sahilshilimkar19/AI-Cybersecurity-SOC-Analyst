"""Integration tests for persisting threat assessments.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. The property under test is
supersession: an investigation's understanding changes, and the record of what
was believed at each point has to survive that change.
"""

import pytest
from sqlalchemy.orm import Session

from backend.db.orm.investigation import Investigation
from backend.db.repositories.analysis import ThreatAssessmentRepository
from backend.services.assessment import record_threat_assessment, to_threat_assessment
from models.enums import EnrichmentStatus, Severity, TriagePriority, TriggerSource, Verdict
from models.threat import (
    IocIndicator,
    IocReputation,
    IocType,
    SeverityAssessment,
    TechniqueMapping,
    ThreatDetectionResult,
)
from models.values import Citation


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    record = Investigation(trigger_source=TriggerSource.ALERT, title="assessment fixture")
    db_session.add(record)
    db_session.flush()
    return record


def _result(
    *,
    verdict: Verdict = Verdict.MALICIOUS,
    level: Severity = Severity.HIGH,
    enriched: bool = True,
    escalate: bool = False,
) -> ThreatDetectionResult:
    return ThreatDetectionResult(
        investigation_id="inv-1",
        verdict=verdict,
        severity=SeverityAssessment(
            score=8.0, level=level, rationale="High (8.0/10): corroborated intrusion."
        ),
        triage_priority=TriagePriority.HIGH,
        iocs=[
            IocIndicator(
                type=IocType.IP_ADDRESS,
                value="203.0.113.44",
                defanged="203[.]0[.]113[.]44",
                event_ids=["evt-1"],
                observation_count=6,
                reputation=IocReputation.MALICIOUS if enriched else IocReputation.UNKNOWN,
                reputation_source="virustotal" if enriched else None,
                enriched=enriched,
            )
        ],
        attack_techniques=[
            TechniqueMapping(
                technique_id="T1110",
                name="Brute Force",
                tactics=["Credential Access"],
                rationale="repeated authentication failures",
                event_ids=["evt-1"],
                confidence=0.9,
                citations=[
                    Citation(
                        source_id="mitre_attack",
                        source="MITRE ATT&CK",
                        url="https://attack.mitre.org/techniques/T1110/",
                    )
                ],
            )
        ],
        enrichment_status=EnrichmentStatus.COMPLETE if enriched else EnrichmentStatus.UNAVAILABLE,
        escalation_required=escalate,
        escalation_reason="low confidence on a critical finding" if escalate else None,
        confidence=0.82,
    )


def test_an_assessment_round_trips_with_its_reasoning(
    db_session: Session, investigation: Investigation
) -> None:
    row = record_threat_assessment(db_session, investigation.id, _result())

    assert row.verdict is Verdict.MALICIOUS
    assert row.severity is Severity.HIGH
    assert row.triage_priority is TriagePriority.HIGH
    assert row.confidence == pytest.approx(0.82)
    assert "corroborated intrusion" in (row.rationale or "")


def test_indicators_are_stored_defanged_alongside_their_raw_value(
    db_session: Session, investigation: Investigation
) -> None:
    """Anything that renders an indicator gets an inert form without asking."""
    row = record_threat_assessment(db_session, investigation.id, _result())

    (ioc,) = row.iocs
    assert ioc["value"] == "203.0.113.44"
    assert ioc["defanged"] == "203[.]0[.]113[.]44"


def test_an_unchecked_indicator_is_stored_without_a_source(
    db_session: Session, investigation: Investigation
) -> None:
    row = record_threat_assessment(db_session, investigation.id, _result(enriched=False))

    (ioc,) = row.iocs
    assert ioc["reputation"] == "unknown"
    assert ioc["source"] is None
    assert ioc["enriched"] is False


def test_techniques_are_stored_with_their_citations(
    db_session: Session, investigation: Investigation
) -> None:
    row = record_threat_assessment(db_session, investigation.id, _result())

    (technique,) = row.attack_techniques
    assert technique["technique_id"] == "T1110"
    assert technique["tactics"] == ["Credential Access"]
    assert technique["citations"][0]["url"].endswith("/T1110/")


def test_an_escalation_reason_is_kept_with_the_rationale(
    db_session: Session, investigation: Investigation
) -> None:
    row = record_threat_assessment(db_session, investigation.id, _result(escalate=True))
    assert "Escalation required" in (row.rationale or "")


def test_a_revised_assessment_supersedes_rather_than_overwrites(
    db_session: Session, investigation: Investigation
) -> None:
    first = record_threat_assessment(
        db_session, investigation.id, _result(verdict=Verdict.SUSPICIOUS)
    )
    second = record_threat_assessment(db_session, investigation.id, _result())

    assert first.version == 1
    assert second.version == 2

    repository = ThreatAssessmentRepository(db_session)
    history = repository.history(investigation.id)
    assert [row.verdict for row in history] == [Verdict.SUSPICIOUS, Verdict.MALICIOUS]


def test_the_current_assessment_is_the_latest_version(
    db_session: Session, investigation: Investigation
) -> None:
    record_threat_assessment(db_session, investigation.id, _result(verdict=Verdict.SUSPICIOUS))
    record_threat_assessment(db_session, investigation.id, _result())

    current = ThreatAssessmentRepository(db_session).current(investigation.id)
    assert current is not None
    assert current.verdict is Verdict.MALICIOUS
    assert current.version == 2


def test_an_investigation_with_no_assessment_reports_none(
    db_session: Session, investigation: Investigation
) -> None:
    repository = ThreatAssessmentRepository(db_session)
    assert repository.current(investigation.id) is None
    assert repository.latest_version(investigation.id) == 0


def test_versions_are_isolated_per_investigation(db_session: Session) -> None:
    first = Investigation(trigger_source=TriggerSource.ALERT, title="one")
    second = Investigation(trigger_source=TriggerSource.ALERT, title="two")
    db_session.add_all([first, second])
    db_session.flush()

    record_threat_assessment(db_session, first.id, _result())
    record_threat_assessment(db_session, first.id, _result())
    row = record_threat_assessment(db_session, second.id, _result())

    assert row.version == 1


def test_mapping_is_pure_and_does_not_touch_the_session() -> None:
    """The mapper is usable without a database, which keeps it unit-testable."""
    from uuid import uuid4

    row = to_threat_assessment(uuid4(), _result(), version=3)
    assert row.version == 3
    assert row.enrichment_status is EnrichmentStatus.COMPLETE

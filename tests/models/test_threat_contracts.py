"""Tests for the threat-detection contracts.

These assert the rules the *types* are supposed to enforce, so a future change
that weakens one shows up here rather than in an incident.
"""

import pytest
from pydantic import ValidationError

from models.enums import EnrichmentStatus, Severity, Verdict
from models.threat import (
    AssessmentClaim,
    ClaimKind,
    DetectionSignal,
    IocIndicator,
    IocReputation,
    IocType,
    SeverityAssessment,
    ThreatDetectionResult,
)


def _ioc(**overrides: object) -> IocIndicator:
    payload: dict[str, object] = {
        "type": IocType.IP_ADDRESS,
        "value": "203.0.113.9",
        "defanged": "203[.]0[.]113[.]9",
    }
    payload.update(overrides)
    return IocIndicator(**payload)


def _result(**overrides: object) -> ThreatDetectionResult:
    payload: dict[str, object] = {
        "investigation_id": "inv-1",
        "severity": SeverityAssessment(score=0.0, level=Severity.INFO),
    }
    payload.update(overrides)
    return ThreatDetectionResult(**payload)


def test_an_indicator_defaults_to_unchecked_and_unknown() -> None:
    ioc = _ioc()
    assert ioc.reputation is IocReputation.UNKNOWN
    assert ioc.enriched is False
    assert ioc.reputation_source is None


def test_an_unchecked_indicator_is_never_hostile() -> None:
    """A reputation without a source cannot count as an assertion about the world."""
    assert _ioc(reputation=IocReputation.MALICIOUS, enriched=False).is_hostile is False


def test_a_confirmed_indicator_is_hostile() -> None:
    ioc = _ioc(reputation=IocReputation.MALICIOUS, enriched=True, reputation_source="virustotal")
    assert ioc.is_hostile is True


def test_a_confirmed_clean_indicator_is_not_hostile() -> None:
    ioc = _ioc(reputation=IocReputation.HARMLESS, enriched=True, reputation_source="virustotal")
    assert ioc.is_hostile is False


def test_an_assessment_defaults_to_the_conservative_position() -> None:
    """Absent evidence, the default must be benign *and* explicitly unenriched."""
    result = _result()
    assert result.verdict is Verdict.BENIGN
    assert result.enrichment_status is EnrichmentStatus.UNAVAILABLE
    assert result.escalation_required is False
    assert result.knowledge_grounded is False
    assert result.confidence == 0.0


def test_claims_partition_into_observations_and_inferences() -> None:
    result = _result(
        claims=[
            AssessmentClaim(kind=ClaimKind.OBSERVATION, statement="five failures"),
            AssessmentClaim(kind=ClaimKind.INFERENCE, statement="probable guessing"),
        ]
    )
    assert [claim.statement for claim in result.observations] == ["five failures"]
    assert [claim.statement for claim in result.inferences] == ["probable guessing"]
    assert len(result.claims) == len(result.observations) + len(result.inferences)


def test_hostile_indicators_are_filtered_to_the_confirmed_ones() -> None:
    result = _result(
        iocs=[
            _ioc(reputation=IocReputation.MALICIOUS, enriched=False),
            _ioc(
                value="198.51.100.7",
                defanged="198[.]51[.]100[.]7",
                reputation=IocReputation.MALICIOUS,
                enriched=True,
            ),
        ]
    )
    assert [ioc.value for ioc in result.hostile_iocs] == ["198.51.100.7"]


def test_severity_is_bounded_to_the_cvss_scale() -> None:
    with pytest.raises(ValidationError):
        SeverityAssessment(score=11.0, level=Severity.CRITICAL)


def test_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        _result(confidence=1.5)


def test_a_signal_weight_is_bounded() -> None:
    with pytest.raises(ValidationError):
        DetectionSignal(rule_id="r", name="n", description="d", weight=12.0)


def test_contracts_reject_unknown_fields() -> None:
    """Strict contracts: a typo becomes an error, not a silently dropped field."""
    with pytest.raises(ValidationError):
        _ioc(reputaton=IocReputation.MALICIOUS)

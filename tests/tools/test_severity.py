"""Tests for severity scoring, verdict derivation, triage priority, and escalation.

These pin the calibration decisions rather than the arithmetic: gaps must not
reduce severity, context-only rules must not corroborate, and an ambiguous
high-impact case must escalate.
"""

import pytest

from models.enums import Severity, TriagePriority, Verdict
from models.threat import DetectionSignal, IocIndicator, IocReputation, IocType
from tools.severity import (
    CORROBORATION_MIN_WEIGHT,
    assess_escalation,
    corroborating_rules,
    derive_priority,
    derive_verdict,
    score_severity,
    severity_level,
)


def _signal(rule_id: str, weight: float, *, events: list[str] | None = None) -> DetectionSignal:
    return DetectionSignal(
        rule_id=rule_id,
        name=rule_id.replace("_", " "),
        description="test signal",
        weight=weight,
        event_ids=events or ["e1"],
    )


def _ioc(reputation: IocReputation, *, enriched: bool = True) -> IocIndicator:
    return IocIndicator(
        type=IocType.IP_ADDRESS,
        value="203.0.113.9",
        defanged="203[.]0[.]113[.]9",
        reputation=reputation,
        reputation_source="test-intel" if enriched else None,
        enriched=enriched,
    )


# --- Bands ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (2.0, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_bands_match_cvss(score: float, expected: Severity) -> None:
    assert severity_level(score) is expected


# --- Scoring ----------------------------------------------------------------


def test_no_signals_score_zero_and_say_so() -> None:
    assessment = score_severity([])
    assert assessment.score == 0.0
    assert assessment.level is Severity.INFO
    assert assessment.factors == ["no signals fired"]


def test_the_strongest_signal_sets_the_floor() -> None:
    assessment = score_severity([_signal("heavy", 8.0)])
    assert assessment.score == 8.0
    assert "heavy" in assessment.factors[0]


def test_independent_rules_corroborate_and_raise_the_score() -> None:
    one = score_severity([_signal("a", 6.0)])
    three = score_severity([_signal("a", 6.0), _signal("b", 5.0), _signal("c", 4.5)])
    assert three.score > one.score


def test_corroboration_is_capped_so_volume_cannot_manufacture_a_critical() -> None:
    many = [_signal(f"rule_{index}", 5.0) for index in range(12)]
    assert score_severity(many).score <= 7.0


def test_context_only_rules_do_not_corroborate() -> None:
    """A heavy rule and the low-weight rule beside it are usually one event."""
    weak = CORROBORATION_MIN_WEIGHT - 1.0
    with_context = score_severity([_signal("heavy", 7.5), _signal("context", weak)])
    alone = score_severity([_signal("heavy", 7.5)])

    assert with_context.score == alone.score
    assert any("context-only" in factor for factor in with_context.factors)


def test_context_only_rules_are_still_reported() -> None:
    assessment = score_severity([_signal("heavy", 7.5), _signal("chatter", 2.5)])
    assert any("chatter" in factor for factor in assessment.factors)


def test_a_critical_asset_raises_the_stakes() -> None:
    plain = score_severity([_signal("a", 6.0)])
    critical = score_severity([_signal("a", 6.0)], critical_assets_involved=["db-prod"])

    assert critical.score > plain.score
    assert any("db-prod" in factor for factor in critical.factors)


def test_the_score_is_capped_at_ten() -> None:
    signals = [_signal(f"rule_{index}", 9.5) for index in range(6)]
    assert score_severity(signals, critical_assets_involved=["db-prod"]).score == 10.0


def test_every_contribution_is_recorded_so_it_can_be_disputed() -> None:
    assessment = score_severity(
        [_signal("a", 8.0), _signal("b", 5.0)], critical_assets_involved=["db-prod"]
    )
    assert len(assessment.factors) >= 3
    assert assessment.rationale


# --- Verdict ----------------------------------------------------------------


def test_no_signals_is_benign() -> None:
    assert derive_verdict(score_severity([]), [], []) is Verdict.BENIGN


def test_one_strong_rule_alone_is_suspicious_not_malicious() -> None:
    signals = [_signal("heavy", 8.0)]
    assert derive_verdict(score_severity(signals), signals, []) is Verdict.SUSPICIOUS


def test_corroborated_high_severity_is_malicious() -> None:
    signals = [_signal("heavy", 8.0), _signal("other", 6.0)]
    assert derive_verdict(score_severity(signals), signals, []) is Verdict.MALICIOUS


def test_a_context_rule_cannot_supply_the_second_opinion() -> None:
    signals = [_signal("heavy", 8.0), _signal("context", 2.5)]
    assert derive_verdict(score_severity(signals), signals, []) is Verdict.SUSPICIOUS


def test_confirmed_hostile_intelligence_is_decisive() -> None:
    signals = [_signal("weak", 4.5)]
    verdict = derive_verdict(score_severity(signals), signals, [_ioc(IocReputation.MALICIOUS)])
    assert verdict is Verdict.MALICIOUS


def test_an_unchecked_indicator_does_not_harden_the_verdict() -> None:
    signals = [_signal("weak", 4.5)]
    unchecked = _ioc(IocReputation.MALICIOUS, enriched=False)
    assert derive_verdict(score_severity(signals), signals, [unchecked]) is Verdict.SUSPICIOUS


# --- Priority ---------------------------------------------------------------


def test_benign_is_always_low_priority() -> None:
    assessment = score_severity([_signal("a", 9.5)])
    assert derive_priority(Verdict.BENIGN, assessment) is TriagePriority.LOW


def test_critical_severity_is_urgent() -> None:
    assessment = score_severity([_signal("a", 9.5)])
    assert derive_priority(Verdict.MALICIOUS, assessment) is TriagePriority.URGENT


def test_a_critical_asset_outranks_raw_severity() -> None:
    """Priority answers 'what does this cost if it waits?', not 'how bad is it?'."""
    medium = score_severity([_signal("a", 5.0)])
    assert derive_priority(Verdict.SUSPICIOUS, medium) is TriagePriority.MEDIUM
    assert (
        derive_priority(Verdict.SUSPICIOUS, medium, critical_asset_involved=True)
        is TriagePriority.HIGH
    )


def test_malicious_on_a_critical_asset_is_urgent() -> None:
    high = score_severity([_signal("a", 7.5)])
    assert (
        derive_priority(Verdict.MALICIOUS, high, critical_asset_involved=True)
        is TriagePriority.URGENT
    )


def test_low_severity_stays_low() -> None:
    low = score_severity([_signal("a", 2.0)])
    assert derive_priority(Verdict.SUSPICIOUS, low) is TriagePriority.LOW


# --- Escalation -------------------------------------------------------------


def test_a_confident_conclusive_finding_does_not_need_escalation() -> None:
    high = score_severity([_signal("a", 8.0), _signal("b", 6.0)])
    escalate, reason = assess_escalation(Verdict.MALICIOUS, high, confidence=0.9)
    assert escalate is False
    assert reason is None


def test_low_confidence_on_a_high_impact_case_escalates() -> None:
    high = score_severity([_signal("a", 8.0), _signal("b", 6.0)])
    escalate, reason = assess_escalation(Verdict.MALICIOUS, high, confidence=0.4)
    assert escalate is True
    assert reason is not None and "confidence" in reason


def test_uncertainty_about_something_small_is_noise_not_escalation() -> None:
    low = score_severity([_signal("a", 2.0)])
    assert assess_escalation(Verdict.SUSPICIOUS, low, confidence=0.2) == (False, None)


def test_a_high_impact_case_with_missing_evidence_escalates() -> None:
    high = score_severity([_signal("a", 8.0), _signal("b", 6.0)])
    escalate, reason = assess_escalation(
        Verdict.MALICIOUS, high, confidence=0.9, coverage_gaps=["source_unavailable: siem"]
    )
    assert escalate is True
    assert reason is not None and "coverage gap" in reason


def test_an_inconclusive_high_impact_case_escalates() -> None:
    high = score_severity([_signal("a", 8.0)])
    escalate, reason = assess_escalation(Verdict.SUSPICIOUS, high, confidence=0.9)
    assert escalate is True
    assert reason is not None and "suspicious" in reason


def test_a_benign_verdict_never_escalates() -> None:
    assessment = score_severity([])
    assert assess_escalation(Verdict.BENIGN, assessment, confidence=0.1) == (False, None)


def test_a_medium_finding_on_a_critical_asset_can_escalate() -> None:
    medium = score_severity([_signal("a", 5.0)])
    escalate, _ = assess_escalation(
        Verdict.SUSPICIOUS, medium, confidence=0.3, critical_asset_involved=True
    )
    assert escalate is True


# --- Helper -----------------------------------------------------------------


def test_corroborating_rules_filters_by_weight() -> None:
    signals = [_signal("heavy", 8.0), _signal("light", 1.0), _signal("heavy", 8.0)]
    assert corroborating_rules(signals) == {"heavy"}

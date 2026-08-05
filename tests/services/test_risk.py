"""Tests for the shared risk prioritizer.

These pin the judgement the module exists to make: risk is not severity, and the
difference is what decides queue order.
"""

import pytest

from models.enums import Severity, TriagePriority, Verdict
from models.remediation import RiskScore
from services.risk import (
    RiskInputs,
    combine_risk,
    derive_priority,
    score_risk,
    verdict_severity_floor,
)


def _inputs(**overrides: object) -> RiskInputs:
    payload: dict[str, object] = {"severity_score": 5.0}
    payload.update(overrides)
    return RiskInputs(**payload)  # type: ignore[arg-type]


# --- Scoring ----------------------------------------------------------------


def test_severity_alone_is_the_baseline() -> None:
    assessment = score_risk(_inputs(severity_score=7.5))
    assert assessment.score == 7.5
    assert assessment.level is Severity.HIGH


def test_observed_exploitation_raises_risk_most() -> None:
    """A vulnerability someone is using is a different problem from one that exists."""
    plain = score_risk(_inputs())
    exploited = score_risk(_inputs(exploitation_observed=True))
    reachable = score_risk(_inputs(internet_reachable=True))

    assert exploited.score > reachable.score > plain.score


def test_a_critical_asset_raises_risk() -> None:
    assert score_risk(_inputs(asset_critical=True)).score > score_risk(_inputs()).score


def test_unconfirmed_applicability_discounts_rather_than_removes() -> None:
    """A candidate is a lead to check, not an exposure to fix — but still a lead."""
    confirmed = score_risk(_inputs(severity_score=9.0))
    candidate = score_risk(_inputs(severity_score=9.0, applicability_confirmed=False))

    assert 0.0 < candidate.score < confirmed.score


def test_the_score_is_capped_at_ten() -> None:
    saturated = score_risk(
        _inputs(
            severity_score=10.0,
            exploitation_observed=True,
            internet_reachable=True,
            asset_critical=True,
        )
    )
    assert saturated.score == 10.0


def test_every_contribution_is_named_so_it_can_be_argued_with() -> None:
    assessment = score_risk(
        _inputs(exploitation_observed=True, internet_reachable=True, asset_critical=True)
    )
    names = {factor.name for factor in assessment.factors}

    assert names == {"severity", "exploitation_observed", "internet_reachable", "critical_asset"}
    assert assessment.rationale


def test_the_discount_is_recorded_as_a_negative_factor() -> None:
    assessment = score_risk(_inputs(applicability_confirmed=False))
    discount = next(f for f in assessment.factors if f.name == "unconfirmed_applicability")
    assert discount.weight < 0


def test_a_zero_severity_finding_scores_zero() -> None:
    assert score_risk(_inputs(severity_score=0.0)).score == 0.0


# --- Priority ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.5, TriagePriority.URGENT),
        (7.5, TriagePriority.HIGH),
        (5.0, TriagePriority.MEDIUM),
        (1.0, TriagePriority.LOW),
        (0.0, TriagePriority.LOW),
    ],
)
def test_priority_follows_the_risk_bands(score: float, expected: TriagePriority) -> None:
    assert derive_priority(score_risk(_inputs(severity_score=score))) is expected


def test_observed_exploitation_forces_urgency_regardless_of_score() -> None:
    """A live intrusion does not queue behind a vulnerability nobody is touching."""
    low = score_risk(_inputs(severity_score=1.0))
    assert derive_priority(low, exploitation_observed=True) is TriagePriority.URGENT


# --- Combining --------------------------------------------------------------


def test_the_plan_takes_its_worst_finding_not_its_average() -> None:
    """Averaging lets a pile of low-risk items hide the one that matters."""
    scores = [
        score_risk(_inputs(severity_score=1.0)),
        score_risk(_inputs(severity_score=1.0)),
        score_risk(_inputs(severity_score=9.5)),
    ]
    assert combine_risk(scores).score == 9.5


def test_combining_nothing_yields_an_explicit_zero() -> None:
    combined = combine_risk([], subject="investigation inv-1")
    assert combined.score == 0.0
    assert "No remediable finding" in combined.rationale


def test_the_combined_rationale_names_how_many_findings_it_spans() -> None:
    combined = combine_risk([score_risk(_inputs()), score_risk(_inputs(severity_score=8.0))])
    assert "2 finding(s)" in combined.rationale


def test_combining_carries_the_worst_findings_factors() -> None:
    worst = score_risk(_inputs(severity_score=9.0, exploitation_observed=True))
    combined = combine_risk([score_risk(_inputs(severity_score=1.0)), worst])
    assert combined.factors == worst.factors


# --- Verdict floor ----------------------------------------------------------


def test_a_malicious_verdict_floors_risk_even_with_no_cve() -> None:
    """The intrusion happened whether or not a vulnerability was ever named."""
    assert verdict_severity_floor(Verdict.MALICIOUS) >= 7.0
    assert verdict_severity_floor(Verdict.SUSPICIOUS) >= 4.0
    assert verdict_severity_floor(Verdict.BENIGN) == 0.0


def test_the_floor_orders_by_verdict_seriousness() -> None:
    assert (
        verdict_severity_floor(Verdict.MALICIOUS)
        > verdict_severity_floor(Verdict.SUSPICIOUS)
        > verdict_severity_floor(Verdict.BENIGN)
    )


def test_a_risk_score_is_a_domain_contract() -> None:
    assert isinstance(score_risk(_inputs()), RiskScore)

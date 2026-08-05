"""Risk prioritization — shared domain rules (EDS §3.8, §4.6).

Severity answers *how bad is this flaw*. Risk answers *how much does it matter
here*. They are different numbers and conflating them is how remediation queues
end up sorted by CVSS: a critical vulnerability on a decommissioned lab box
outranking a medium one on the payment gateway, forever, until an analyst gives
up on the queue and works from memory instead.

This module lives in ``services/`` rather than in ``tools/`` because it is not an
agent capability. The Patch Recommendation agent orders its plan with it, and the
backend will order the analyst's queue with the same function — one definition of
"what should we do first", not two that drift.

Four factors raise risk above raw severity, and each is here because it changes
what an analyst should do next:

* **Exploitation observed** weighs most. A vulnerability someone is *using* is a
  different problem from one that merely exists, and it is the only factor that
  reflects the present tense.
* **Internet reachability** turns an internal exposure into a public one.
* **Asset criticality** is where the business, not the scanner, gets a vote.
* **Unconfirmed applicability** discounts rather than adds: a candidate is a lead
  to check, not an exposure to fix, and letting candidates score like
  confirmations fills the top of the queue with maybes.

The 0-10 scale and its bands are shared with severity — deliberately reusing
``tools.severity.severity_level`` rather than restating the thresholds, because
two copies of a band table eventually disagree and nobody notices which one the
UI used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from models.enums import TriagePriority, Verdict
from models.remediation import RiskFactor, RiskScore
from tools.severity import severity_level

if TYPE_CHECKING:
    from collections.abc import Sequence

# Additive weights, in the same 0-10 units as the score they adjust.
EXPLOITATION_WEIGHT = 1.5
INTERNET_REACHABLE_WEIGHT = 1.0
CRITICAL_ASSET_WEIGHT = 1.0

# Multiplier applied when applicability was never confirmed. A discount rather
# than a penalty: the finding stays on the list, lower down, where a lead belongs.
UNCONFIRMED_DISCOUNT = 0.6

# Risk at or above which remediation is urgent even without exploitation.
_URGENT_SCORE = 9.0
_HIGH_SCORE = 7.0
_MEDIUM_SCORE = 4.0


@dataclass(frozen=True)
class RiskInputs:
    """Everything the prioritizer is allowed to consider.

    A frozen record rather than a long parameter list, so adding a factor is a
    visible change to the contract instead of a new keyword nobody notices.
    """

    severity_score: float
    applicability_confirmed: bool = True
    exploitation_observed: bool = False
    internet_reachable: bool = False
    asset_critical: bool = False
    subject: str = "this finding"


def score_risk(inputs: RiskInputs) -> RiskScore:
    """Score how much a finding matters in this environment."""
    factors = [
        RiskFactor(
            name="severity",
            weight=round(inputs.severity_score, 2),
            detail=f"base severity of {inputs.subject}",
        )
    ]
    score = inputs.severity_score

    if inputs.exploitation_observed:
        score += EXPLOITATION_WEIGHT
        factors.append(
            RiskFactor(
                name="exploitation_observed",
                weight=EXPLOITATION_WEIGHT,
                detail="the investigation tied observed activity to this finding",
            )
        )
    if inputs.internet_reachable:
        score += INTERNET_REACHABLE_WEIGHT
        factors.append(
            RiskFactor(
                name="internet_reachable",
                weight=INTERNET_REACHABLE_WEIGHT,
                detail="exploitable over the network without credentials or user interaction",
            )
        )
    if inputs.asset_critical:
        score += CRITICAL_ASSET_WEIGHT
        factors.append(
            RiskFactor(
                name="critical_asset",
                weight=CRITICAL_ASSET_WEIGHT,
                detail="a business-critical asset is affected",
            )
        )
    if not inputs.applicability_confirmed:
        discounted = score * UNCONFIRMED_DISCOUNT
        factors.append(
            RiskFactor(
                name="unconfirmed_applicability",
                weight=-round(score - discounted, 2),
                detail="applicability was not confirmed against the asset inventory",
            )
        )
        score = discounted

    final = round(min(10.0, max(0.0, score)), 1)
    level = severity_level(final)
    return RiskScore(
        score=final,
        level=level,
        rationale=(
            f"{level.value.title()} risk ({final}/10) for {inputs.subject}: "
            + ", ".join(factor.name.replace("_", " ") for factor in factors)
            + "."
        ),
        factors=factors,
    )


def derive_priority(risk: RiskScore, *, exploitation_observed: bool = False) -> TriagePriority:
    """Order the remediation queue.

    Observed exploitation forces urgency regardless of score: a live intrusion
    does not wait behind a higher-scoring vulnerability nobody is touching.
    """
    if exploitation_observed:
        return TriagePriority.URGENT
    if risk.score >= _URGENT_SCORE:
        return TriagePriority.URGENT
    if risk.score >= _HIGH_SCORE:
        return TriagePriority.HIGH
    if risk.score >= _MEDIUM_SCORE:
        return TriagePriority.MEDIUM
    return TriagePriority.LOW


def combine_risk(scores: Sequence[RiskScore], *, subject: str = "this investigation") -> RiskScore:
    """Roll individual risks up into one figure for the whole plan.

    The maximum, not the mean. An investigation is as urgent as its worst
    unaddressed finding, and averaging lets a pile of low-risk items dilute the
    one that matters into invisibility.
    """
    if not scores:
        return RiskScore(
            score=0.0,
            level=severity_level(0.0),
            rationale=f"No remediable finding was identified for {subject}.",
            factors=[],
        )

    worst = max(scores, key=lambda item: item.score)
    return RiskScore(
        score=worst.score,
        level=worst.level,
        rationale=(
            f"{worst.level.value.title()} overall risk ({worst.score}/10) for {subject}, "
            f"set by its most serious of {len(scores)} finding(s): {worst.rationale}"
        ),
        factors=worst.factors,
    )


def verdict_severity_floor(verdict: Verdict) -> float:
    """The minimum severity an assessed verdict implies.

    A malicious verdict with no confirmed CVE still warrants remediation — the
    intrusion happened whether or not a vulnerability was ever identified — so
    the verdict supplies a floor the finding-level scores cannot fall below.
    """
    if verdict is Verdict.MALICIOUS:
        return 7.0
    if verdict is Verdict.SUSPICIOUS:
        return 4.0
    return 0.0

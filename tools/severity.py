"""Severity scoring, verdict derivation, and triage priority (EDS §4.3).

The scale is 0-10 with CVSS bands, so a severity here reads the same way as a
severity on a CVE and the two can be compared without a translation table.

Two judgements in this module are worth stating outright, because they are the
ones a reviewer should challenge:

* **Missing evidence lowers confidence, never severity.** A gap in the logs does
  not make an intrusion smaller; it makes the assessment less certain. Scoring
  gaps as mitigation would systematically under-rate exactly the incidents where
  an attacker succeeded in destroying the record.
* **One strong rule is suspicious; corroboration makes it malicious.** A single
  heuristic firing — however heavy — is a lead. Independent behaviors pointing
  the same way, or an external source confirming an indicator, is a finding. This
  is what keeps a lone noisy rule from declaring an incident on its own.
* **Only substantive rules corroborate.** The catalogue deliberately includes
  low-weight context rules ("an interpreter was launched"), and those routinely
  fire on the *same* event as the serious rule beside them. Counting them as
  independent agreement would let one event corroborate itself, so they inform
  the analyst without moving the score.

Everything here is deterministic arithmetic and every contribution is recorded in
``factors``, so a human can disagree with a specific term rather than with an
opaque number.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from models.enums import Severity, TriagePriority, Verdict
from models.threat import SeverityAssessment

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.threat import DetectionSignal, IocIndicator

# CVSS-aligned bands, checked in descending order.
_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)

# Score added per additional *distinct* rule beyond the strongest, and the cap on
# that contribution — corroboration should matter, but volume should not be able
# to manufacture a critical on its own.
_CORROBORATION_STEP = 0.5
_CORROBORATION_CAP = 2.0

# Weight below which a rule is context rather than corroboration. Rules under
# this line still appear in the assessment and still map to techniques; they just
# do not add to the score or harden the verdict.
CORROBORATION_MIN_WEIGHT = 4.0

# Compromise of a designated critical asset raises the stakes, not the evidence.
_CRITICAL_ASSET_BONUS = 1.0

# Distinct rules required alongside a high score before the verdict hardens.
_MALICIOUS_RULE_COUNT = 2
_MALICIOUS_SCORE = 7.0

# Below this, an assessment is treated as ambiguous for escalation purposes.
_AMBIGUITY_CONFIDENCE = 0.6


def corroborating_rules(signals: Sequence[DetectionSignal]) -> set[str]:
    """The distinct rules substantive enough to count as independent agreement."""
    return {signal.rule_id for signal in signals if signal.weight >= CORROBORATION_MIN_WEIGHT}


def severity_level(score: float) -> Severity:
    """Map a 0-10 score onto the severity scale."""
    for threshold, level in _SEVERITY_BANDS:
        if score >= threshold:
            return level
    return Severity.INFO


def score_severity(
    signals: Sequence[DetectionSignal],
    *,
    critical_assets_involved: Sequence[str] = (),
) -> SeverityAssessment:
    """Score severity from the fired signals and the assets they touched."""
    if not signals:
        return SeverityAssessment(
            score=0.0,
            level=Severity.INFO,
            rationale="No detection heuristic matched the available evidence.",
            factors=["no signals fired"],
        )

    strongest = max(signals, key=lambda signal: signal.weight)
    corroborating = corroborating_rules(signals)
    factors = [f"strongest signal {strongest.rule_id!r} contributes {strongest.weight:.1f}"]

    corroboration = min(_CORROBORATION_CAP, _CORROBORATION_STEP * (len(corroborating) - 1))
    corroboration = max(0.0, corroboration)
    if corroboration:
        factors.append(
            f"{len(corroborating)} substantive rules corroborate, adding {corroboration:.1f}"
        )
    context_only = {signal.rule_id for signal in signals} - corroborating
    if context_only:
        factors.append(
            f"{len(context_only)} context-only rule(s) recorded without affecting the score: "
            f"{', '.join(sorted(context_only))}"
        )

    asset_bonus = _CRITICAL_ASSET_BONUS if critical_assets_involved else 0.0
    if asset_bonus:
        factors.append(
            f"critical asset(s) {', '.join(sorted(critical_assets_involved))} involved, "
            f"adding {asset_bonus:.1f}"
        )

    score = round(min(10.0, strongest.weight + corroboration + asset_bonus), 1)
    level = severity_level(score)
    return SeverityAssessment(
        score=score,
        level=level,
        rationale=(
            f"{level.value.title()} ({score}/10): {strongest.name.lower()} "
            f"with {len(corroborating)} substantive detection(s) across "
            f"{len({event_id for signal in signals for event_id in signal.event_ids})} event(s)."
        ),
        factors=factors,
    )


def derive_verdict(
    severity: SeverityAssessment,
    signals: Sequence[DetectionSignal],
    iocs: Sequence[IocIndicator],
) -> Verdict:
    """Decide benign / suspicious / malicious from evidence, never from a hunch.

    Confirmed hostile intelligence is decisive because it is an external
    assertion about a specific indicator. Absent that, a malicious verdict needs
    both a high score and independent corroboration — where "independent" means
    substantive rules, so a heavy rule and the context rule that fired on the
    same event cannot corroborate each other.
    """
    if not signals:
        return Verdict.BENIGN
    if any(ioc.is_hostile for ioc in iocs):
        return Verdict.MALICIOUS

    corroborating = corroborating_rules(signals)
    if severity.score >= _MALICIOUS_SCORE and len(corroborating) >= _MALICIOUS_RULE_COUNT:
        return Verdict.MALICIOUS
    return Verdict.SUSPICIOUS


def derive_priority(
    verdict: Verdict,
    severity: SeverityAssessment,
    *,
    critical_asset_involved: bool = False,
) -> TriagePriority:
    """Order the queue: what an analyst should look at first, and why.

    Priority is not severity. A medium-severity finding on a critical asset
    outranks a high-severity finding on a lab machine, because priority answers
    "what does this cost if it waits?".
    """
    if verdict is Verdict.BENIGN:
        return TriagePriority.LOW
    if severity.level is Severity.CRITICAL or (
        critical_asset_involved and verdict is Verdict.MALICIOUS
    ):
        return TriagePriority.URGENT
    if severity.level is Severity.HIGH or critical_asset_involved:
        return TriagePriority.HIGH
    if severity.level is Severity.MEDIUM:
        return TriagePriority.MEDIUM
    return TriagePriority.LOW


def assess_escalation(
    verdict: Verdict,
    severity: SeverityAssessment,
    *,
    confidence: float,
    critical_asset_involved: bool = False,
    coverage_gaps: Sequence[str] = (),
) -> tuple[bool, str | None]:
    """Decide whether the case must be escalated rather than routinely approved.

    The rule from the module spec is "ambiguous high-impact cases escalate". Both
    halves matter: certainty about something small is routine, and uncertainty
    about something small is noise. It is uncertainty about something that would
    *hurt* which needs a senior human, and saying so in the output is what stops
    a low-confidence critical finding from being waved through a queue.
    """
    high_impact = severity.level in {Severity.HIGH, Severity.CRITICAL} or critical_asset_involved
    if not high_impact or verdict is Verdict.BENIGN:
        return False, None

    if confidence < _AMBIGUITY_CONFIDENCE:
        return True, (
            f"{severity.level.value} severity assessed with low confidence "
            f"({confidence:.2f}); the evidence is not conclusive enough to route routinely."
        )
    if coverage_gaps:
        return True, (
            f"{severity.level.value} severity assessed with {len(coverage_gaps)} coverage gap(s); "
            "part of the evidence picture is missing."
        )
    if verdict is Verdict.SUSPICIOUS:
        return True, (
            f"{severity.level.value} severity but the verdict is suspicious rather than "
            "conclusive; a human should decide before anything follows from it."
        )
    return False, None

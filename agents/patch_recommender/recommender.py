"""The Patch Recommendation agent (EDS §4.6, SAD §2.5).

The last agent in the pipeline, and the only one that proposes changing the
world rather than describing it. Everything before it produced statements about
what happened; this one produces a work list — which is precisely the point at
which an assistive system can quietly turn into an autonomous one.

So the shape of what it emits matters more than the cleverness of what it says.
Every recommendation is a :class:`~models.remediation.RemediationRecommendation`,
a structure with no field capable of holding something a machine could run, whose
``requires_human_approval`` is ``Literal[True]`` and whose approval status cannot
be created as anything but pending. The agent could not dispatch an action if it
tried, and neither can a later change that nobody reviewed carefully.

Three sources of guidance, in descending order of authority, with the difference
stated on every item:

* a **confirmed CVE** with a fixed version from an advisory — upgrade this to
  that, cited to the advisory;
* an **observed technique or weakness class** — the catalogued mitigation for
  that class, cited to MITRE;
* **nothing specific known** — conservative hardening, explicitly labelled
  generic so it is never mistaken for a fix (SAD §2.5's thin-knowledge path).

Prioritization is risk in *this* environment rather than severity in the
abstract, and it comes from ``services.risk`` — the same function the analyst's
queue will use, so the ordering an analyst sees is the ordering the agent meant.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agents.shared.contracts import AgentDegradation, AgentOutcome
from config.logging import get_logger
from integrations.advisories import UnavailableAdvisorySource
from models.enums import RecommendationType, Verdict
from models.remediation import (
    RemediationConfidence,
    RemediationPlan,
    RemediationRecommendation,
    RemediationSupport,
)
from models.threat import ThreatDetectionResult
from models.vulnerability import CveResearchResult
from prompts.assembly import PATCH_RECOMMENDER_PROMPT
from services.risk import (
    RiskInputs,
    combine_risk,
    derive_priority,
    score_risk,
    verdict_severity_floor,
)
from tools.cwe import normalize_cwe_id
from tools.remediation import (
    RemediationTemplate,
    for_technique,
    for_weakness,
    generic_guidance,
    patch_guidance,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from integrations.advisories import AdvisorySource
    from models.remediation import RemediationPlanRequest, RiskScore
    from models.threat import DetectionSignal
    from models.values import Citation
    from models.vulnerability import CveAssessment

_logger = get_logger(__name__)

AGENT_NAME = "patch_recommender"

# Tools this agent is allow-listed to use (EDS §3.7 least privilege).
ALLOWED_TOOLS = (
    "lookup_advisory",
    "remediation_guidance",
    "score_risk",
    "retrieve_knowledge",
)


class PatchRecommender:
    """Produces a prioritized remediation plan for human approval."""

    def __init__(
        self,
        *,
        advisories: AdvisorySource | None = None,
        max_recommendations: int = 20,
    ) -> None:
        self._advisories = advisories or UnavailableAdvisorySource()
        self._max_recommendations = max_recommendations

    def recommend(self, request: RemediationPlanRequest) -> AgentOutcome[RemediationPlan]:
        """Build the plan, stating what it could not ground."""
        degradations: list[AgentDegradation] = []
        notes: list[str] = []

        threat = _read(ThreatDetectionResult, request.threat_assessment)
        dossier = _read(CveResearchResult, request.vulnerability_dossier)
        if threat is None and dossier is None:
            return self._empty_plan(request, degradations, "no upstream findings to remediate")

        critical = {name.lower() for name in request.critical_assets}
        inventory = _inventory_hosts(request.assets)
        recommendations = [
            *self._from_cves(dossier, threat, critical, degradations),
            *self._from_techniques(threat, dossier, critical, inventory),
        ]
        recommendations = _deduplicate(recommendations)

        if not recommendations and threat is not None and threat.verdict is not Verdict.BENIGN:
            # A non-benign verdict with nothing specific to fix still warrants
            # advice: the intrusion happened whether or not a cause was named.
            recommendations = [self._generic(threat, critical, inventory)]
            notes.append(
                "No specific remediation target was identified, so the plan gives "
                "conservative hardening for the affected assets."
            )

        if not recommendations:
            # An explicit statement, not an absence. "We looked and there is
            # nothing to fix" is a finding a human may later have to defend.
            notes.append(
                "The investigation surfaced no confirmed vulnerability and no adversary "
                "technique with catalogued remediation, so there is nothing to remediate."
            )

        ordered = sorted(recommendations, key=_by_priority)
        if len(ordered) > self._max_recommendations:
            notes.append(
                f"{len(ordered) - self._max_recommendations} lower-priority recommendation(s) "
                f"were held back to keep the plan actionable; re-run to see the full list."
            )
            ordered = ordered[: self._max_recommendations]

        knowledge_limited = bool(ordered) and all(
            item.grounding is RemediationConfidence.GENERIC for item in ordered
        )
        if knowledge_limited:
            degradations.append(
                AgentDegradation(
                    reason="thin_remediation_knowledge",
                    detail=(
                        "no product- or class-specific guidance was available; the plan is "
                        "conservative general hardening"
                    ),
                )
            )

        plan = RemediationPlan(
            investigation_id=request.investigation_id,
            recommendations=ordered,
            overall_risk=combine_risk(
                [item.risk for item in ordered], subject=f"investigation {request.investigation_id}"
            ),
            knowledge_limited=knowledge_limited,
            notes=notes,
            confidence=_confidence(ordered, threat, dossier),
        )

        _logger.info(
            "remediation_plan_complete",
            investigation_id=request.investigation_id,
            recommendations=len(plan.recommendations),
            highest_priority=(plan.highest_priority.value if plan.highest_priority else None),
            overall_risk=plan.overall_risk.score if plan.overall_risk else 0.0,
            knowledge_limited=knowledge_limited,
            confidence=plan.confidence,
        )

        return AgentOutcome(
            agent=AGENT_NAME,
            output=plan,
            confidence=plan.confidence,
            prompt_version=PATCH_RECOMMENDER_PROMPT.version,
            tool_calls=[
                {"tool": "lookup_advisory", "count": len(dossier.cves) if dossier else 0},
                {"tool": "remediation_guidance", "count": len(ordered)},
                {"tool": "score_risk", "count": len(ordered)},
            ],
            degradations=degradations,
        )

    # --- Sources of guidance ----------------------------------------------

    def _from_cves(
        self,
        dossier: CveResearchResult | None,
        threat: ThreatDetectionResult | None,
        critical: set[str],
        degradations: list[AgentDegradation],
    ) -> list[RemediationRecommendation]:
        """Patch guidance for confirmed vulnerabilities, and checks for candidates.

        Confirmed CVEs get an upgrade recommendation; candidates get a *verify*
        recommendation instead, because telling someone to patch software you
        never established they run wastes a change window and erodes trust in
        the whole list.
        """
        if dossier is None:
            return []

        recommendations: list[RemediationRecommendation] = []
        advisory_failures = 0

        for assessment in dossier.cves:
            template, advisory_missing = self._patch_template(assessment)
            advisory_failures += int(advisory_missing)
            recommendations.append(
                self._build(
                    template,
                    assessment=assessment,
                    threat=threat,
                    critical=critical,
                    confirmed=True,
                )
            )

        for assessment in dossier.candidates:
            recommendations.append(
                self._build(
                    _verification_template(assessment),
                    assessment=assessment,
                    threat=threat,
                    critical=critical,
                    confirmed=False,
                )
            )

        if advisory_failures:
            degradations.append(
                AgentDegradation(
                    reason="advisory_unavailable",
                    detail=(
                        f"no fixed version could be resolved for {advisory_failures} "
                        "confirmed CVE(s); the guidance names the advisory instead"
                    ),
                )
            )
        return recommendations

    def _patch_template(self, assessment: CveAssessment) -> tuple[RemediationTemplate, bool]:
        """Upgrade guidance for one CVE, with a fixed version where one is known."""
        product = next(
            (item.product for item in assessment.evidence if item.product),
            next((item.product for item in assessment.record.affected), None),
        )
        if not self._advisories.is_available:
            return (
                patch_guidance(
                    assessment.cve_id,
                    product=product,
                    references=assessment.record.references,
                ),
                True,
            )

        result = self._advisories.fetch(assessment.cve_id)
        if not result.ok or not result.advisories:
            return (
                patch_guidance(
                    assessment.cve_id,
                    product=product,
                    references=assessment.record.references,
                ),
                True,
            )

        advisory = result.advisories[0]
        fix = advisory.fix_for(product)
        return (
            patch_guidance(
                assessment.cve_id,
                product=fix.package if fix else product,
                fixed_version=fix.fixed_version if fix else None,
                references=assessment.record.references,
                advisory_citation=advisory.citation(),
            ),
            fix is None or fix.fixed_version is None,
        )

    def _from_techniques(
        self,
        threat: ThreatDetectionResult | None,
        dossier: CveResearchResult | None,
        critical: set[str],
        inventory: Sequence[str],
    ) -> list[RemediationRecommendation]:
        """Mitigations for the behaviors that were actually observed.

        Distinct from patching: a technique mitigation addresses *how* the
        activity happened, which stays worth doing even when the specific
        vulnerability behind it is patched.
        """
        if threat is None:
            return []

        recommendations: list[RemediationRecommendation] = []
        targets = _affected_hosts(dossier, inventory)
        touches_critical = any(host.lower() in critical for host in targets)
        for mapping in threat.attack_techniques:
            template = for_technique(mapping.technique_id)
            if template is None:
                continue

            # Several techniques legitimately share one mitigation. Each is built
            # separately and merged by _deduplicate, so the surviving item records
            # *every* technique it answers — skipping here would silently drop that
            # attribution and understate what the work covers.
            signals = [
                signal for signal in threat.signals if mapping.technique_id in signal.technique_ids
            ]
            rules = [signal.rule_id for signal in signals]
            risk = self._technique_risk(threat, touches_critical, signals)
            recommendations.append(
                RemediationRecommendation(
                    action=template.action,
                    type=template.type,
                    priority=derive_priority(risk, exploitation_observed=True),
                    risk=risk,
                    rationale=f"{template.rationale} {mapping.rationale}".strip(),
                    expected_impact=template.expected_impact,
                    steps=list(template.steps),
                    verification=template.verification,
                    targets=targets,
                    support=RemediationSupport(
                        technique_ids=[mapping.technique_id], signal_rule_ids=rules
                    ),
                    grounding=template.grounding,
                    citations=[*template.citations(), *mapping.citations],
                )
            )
        return recommendations

    def _generic(
        self, threat: ThreatDetectionResult, critical: set[str], inventory: Sequence[str]
    ) -> RemediationRecommendation:
        """Conservative hardening, labelled as such."""
        template = generic_guidance()
        targets = _affected_hosts(None, inventory)
        risk = self._technique_risk(threat, any(host.lower() in critical for host in targets))
        return RemediationRecommendation(
            action=template.action,
            type=template.type,
            priority=derive_priority(risk),
            risk=risk,
            rationale=f"{template.rationale} {threat.severity.rationale}".strip(),
            expected_impact=template.expected_impact,
            steps=list(template.steps),
            verification=template.verification,
            targets=targets,
            support=RemediationSupport(
                signal_rule_ids=[signal.rule_id for signal in threat.signals] or ["verdict_only"]
            ),
            grounding=template.grounding,
            citations=template.citations(),
        )

    # --- Assembly ---------------------------------------------------------

    def _build(
        self,
        template: RemediationTemplate,
        *,
        assessment: CveAssessment,
        threat: ThreatDetectionResult | None,
        critical: set[str],
        confirmed: bool,
    ) -> RemediationRecommendation:
        """Turn one CVE assessment plus a template into a recommendation."""
        cvss = assessment.record.cvss
        hosts = sorted({item.hostname for item in assessment.evidence if item.hostname})
        risk = score_risk(
            RiskInputs(
                severity_score=cvss.base_score if cvss else 5.0,
                applicability_confirmed=confirmed,
                exploitation_observed=not assessment.exploit_mapping.is_empty,
                internet_reachable=bool(cvss and cvss.remotely_exploitable_without_credentials),
                asset_critical=any(host.lower() in critical for host in hosts),
                subject=assessment.cve_id,
            )
        )
        return RemediationRecommendation(
            action=template.action,
            type=template.type,
            priority=derive_priority(
                risk, exploitation_observed=not assessment.exploit_mapping.is_empty
            ),
            risk=risk,
            rationale=template.rationale,
            expected_impact=template.expected_impact,
            steps=list(template.steps),
            verification=template.verification,
            targets=hosts,
            support=RemediationSupport(
                cve_ids=[assessment.cve_id],
                technique_ids=list(assessment.exploit_mapping.technique_ids),
                cwe_ids=[
                    normalized
                    for cwe_id in assessment.record.cwe_ids
                    if (normalized := normalize_cwe_id(cwe_id))
                ],
            ),
            grounding=template.grounding,
            citations=[*template.citations(), *assessment.citations],
        )

    @staticmethod
    def _technique_risk(
        threat: ThreatDetectionResult,
        touches_critical: bool,
        signals: Sequence[DetectionSignal] = (),
    ) -> RiskScore:
        """Risk for a behavior-driven mitigation, floored by the verdict.

        Scored from the *strongest detection that mapped to this technique*, not
        from the investigation's overall severity. Using the overall figure would
        give every behavioral recommendation the same risk, and a plan where
        everything is equally urgent tells an analyst nothing about what to do
        first — which is the entire job of a prioritized plan.
        """
        strongest = max((signal.weight for signal in signals), default=threat.severity.score)
        floor = verdict_severity_floor(threat.verdict)
        subject = signals[0].name.lower() if signals else "the observed activity"
        return score_risk(
            RiskInputs(
                severity_score=max(strongest, floor),
                applicability_confirmed=True,
                exploitation_observed=True,
                asset_critical=touches_critical,
                subject=subject,
            )
        )

    def _empty_plan(
        self,
        request: RemediationPlanRequest,
        degradations: list[AgentDegradation],
        note: str,
    ) -> AgentOutcome[RemediationPlan]:
        """An investigation with nothing to remediate says so."""
        plan = RemediationPlan(
            investigation_id=request.investigation_id,
            overall_risk=combine_risk([], subject=f"investigation {request.investigation_id}"),
            notes=[note],
        )
        _logger.info("remediation_plan_empty", investigation_id=request.investigation_id, note=note)
        return AgentOutcome(
            agent=AGENT_NAME,
            output=plan,
            confidence=0.0,
            prompt_version=PATCH_RECOMMENDER_PROMPT.version,
            degradations=degradations,
        )


# --- Helpers ----------------------------------------------------------------


def _verification_template(assessment: CveAssessment) -> RemediationTemplate:
    """Guidance for a CVE whose applicability was never confirmed.

    A candidate becomes a *check*, not a patch. Telling someone to patch software
    you never established they run wastes a change window and erodes trust in the
    whole list; the reason it stayed a candidate is carried through, so the
    analyst knows exactly what to go and establish.
    """
    reasons = "; ".join(item.detail for item in assessment.evidence if item.detail)
    weakness = next(
        (
            template
            for cwe_id in assessment.record.cwe_ids
            if (template := for_weakness(cwe_id)) is not None
        ),
        None,
    )
    follow_up = (
        f" If it applies, {weakness.action[0].lower()}{weakness.action[1:]}." if weakness else ""
    )
    return RemediationTemplate(
        template_id=f"verify:{assessment.cve_id}",
        action=f"Establish whether {assessment.cve_id} applies to the affected assets",
        # Investigative work, not a change: deliberately not typed as a patch, so
        # a change-management queue does not treat it as one.
        type=RecommendationType.OTHER,
        rationale=(
            f"{assessment.cve_id} could not be confirmed against the asset inventory. "
            f"{reasons or 'The evidence needed to decide is missing.'} "
            "Leaving an unchecked candidate open leaves a possible exposure unattended."
        ),
        expected_impact=(
            "The candidate is resolved into a confirmed finding or ruled out. No "
            "production change is made by this step."
        ),
        steps=(
            "Record the installed version of the affected product on each candidate host.",
            "Compare it against the published vulnerable range for this CVE.",
            f"Re-run the investigation once the inventory is complete.{follow_up}",
        ),
        verification="Confirm the asset inventory now records a version for the affected product.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        extra_citations=tuple(assessment.citations),
    )


def _affected_hosts(dossier: CveResearchResult | None, inventory: Sequence[str]) -> list[str]:
    """The hosts a behavioral mitigation should be applied to.

    Applicability evidence names hosts precisely, so it is preferred. Falling
    back to the supplied inventory keeps a recommendation addressed to *something*
    rather than to nobody — an unaddressed action is one that never gets picked up.
    """
    hosts = {
        item.hostname
        for assessment in (dossier.cves if dossier else ())
        for item in assessment.evidence
        if item.hostname
    }
    return sorted(hosts or set(inventory))


def _deduplicate(
    recommendations: Sequence[RemediationRecommendation],
) -> list[RemediationRecommendation]:
    """One recommendation per distinct action; merge the support behind it.

    Two techniques mapping to the same mitigation is one piece of work, and
    listing it twice makes a plan look longer than the job actually is.
    """
    merged: dict[str, RemediationRecommendation] = {}
    for item in recommendations:
        existing = merged.get(item.action)
        if existing is None:
            merged[item.action] = item
            continue
        merged[item.action] = existing.model_copy(
            update={
                "support": RemediationSupport(
                    cve_ids=_union(existing.support.cve_ids, item.support.cve_ids),
                    technique_ids=_union(
                        existing.support.technique_ids, item.support.technique_ids
                    ),
                    signal_rule_ids=_union(
                        existing.support.signal_rule_ids, item.support.signal_rule_ids
                    ),
                    cwe_ids=_union(existing.support.cwe_ids, item.support.cwe_ids),
                ),
                "targets": _union(existing.targets, item.targets),
                # The merged item answers both findings, so it takes the worse
                # risk and keeps both sets of sources.
                "risk": existing.risk if existing.risk.score >= item.risk.score else item.risk,
                "citations": _merge_citations(existing.citations, item.citations),
            }
        )
    return list(merged.values())


def _merge_citations(left: Sequence[Citation], right: Sequence[Citation]) -> list[Citation]:
    """Keep every source behind a merged recommendation, deduplicated."""
    seen: set[str] = set()
    merged: list[Citation] = []
    for citation in [*left, *right]:
        key = citation.url or citation.title or citation.source_id
        if key in seen:
            continue
        seen.add(key)
        merged.append(citation)
    return merged


def _union(left: Sequence[str], right: Sequence[str]) -> list[str]:
    return sorted({*left, *right})


def _by_priority(item: RemediationRecommendation) -> tuple[int, float, str]:
    """Most urgent first, then by risk, then by action for a stable order."""
    order = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
    return (order.get(item.priority.value, 4), -item.risk.score, item.action)


_GROUNDING_WEIGHTS = {
    RemediationConfidence.VENDOR_SPECIFIC: 1.0,
    RemediationConfidence.CLASS_SPECIFIC: 0.85,
    RemediationConfidence.GENERIC: 0.6,
}


def _confidence(
    recommendations: Sequence[RemediationRecommendation],
    threat: ThreatDetectionResult | None,
    dossier: CveResearchResult | None,
) -> float:
    """Inherited from the section each recommendation actually rests on.

    Deliberately *not* an average of every upstream confidence. A behavioral
    mitigation derived from the threat assessment does not become less trustworthy
    because CVE research found nothing — averaging in that zero would penalize
    advice the dossier never touched, and the resulting number would say something
    untrue about advice that is perfectly well grounded.

    Grounding then scales it: a vendor-specified fix deserves more confidence than
    the same number of generic hardening items.
    """
    if not recommendations:
        return 0.0

    scored = 0.0
    for item in recommendations:
        source = dossier if item.support.cve_ids and dossier is not None else threat
        upstream = source.confidence if source is not None else 0.5
        scored += upstream * _GROUNDING_WEIGHTS[item.grounding]
    return round(min(1.0, max(0.0, scored / len(recommendations))), 4)


def _read(model: type[Any], payload: dict[str, object] | None) -> Any:
    """Validate an upstream section, or ``None`` if absent or unreadable."""
    if not payload:
        return None
    try:
        return model.model_validate(payload)
    except ValueError:
        _logger.warning("remediation_input_unreadable", section=model.__name__)
        return None


def _inventory_hosts(assets: Sequence[dict[str, object]]) -> list[str]:
    """Hostnames from the seeded asset inventory, tolerating malformed entries."""
    return sorted(
        {
            str(item["hostname"])
            for item in assets
            if isinstance(item, dict) and item.get("hostname")
        }
    )

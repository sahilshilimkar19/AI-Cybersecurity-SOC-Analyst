"""Tests for the Patch Recommendation agent.

This is the agent that proposes changing the world, so most of the suite is about
what it must never do: execute, pre-approve, invent a version, or present generic
advice as a fix.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agents.patch_recommender import ALLOWED_TOOLS, PatchRecommender
from integrations.advisories import Advisory, AdvisoryFix, InMemoryAdvisorySource
from models.enums import (
    ApprovalStatus,
    CveApplicability,
    RecommendationType,
    Severity,
    TriagePriority,
    Verdict,
)
from models.remediation import (
    RemediationConfidence,
    RemediationPlanRequest,
    RemediationRecommendation,
    RiskScore,
)
from models.threat import (
    DetectionSignal,
    SeverityAssessment,
    TechniqueMapping,
    ThreatDetectionResult,
)
from models.values import Citation
from models.vulnerability import (
    ApplicabilityEvidence,
    ApplicabilityReason,
    CveAssessment,
    CveRecord,
    CveResearchResult,
    ExploitMapping,
)
from tools.cvss import interpret

ATTACK_CITATION = Citation(
    source_id="mitre_attack",
    source="MITRE ATT&CK",
    url="https://attack.mitre.org/techniques/T1110/",
)

LOG4SHELL = CveRecord(
    cve_id="CVE-2021-44228",
    summary="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
    cvss=interpret("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", reported_score=10.0),
    cwe_ids=["CWE-502"],
    references=["https://logging.apache.org/log4j/2.x/security.html"],
    modified_at=datetime(2023, 11, 7, tzinfo=UTC),
)

ADVISORY = Advisory(
    advisory_id="GHSA-jfh8-c2jp-5v3q",
    cve_id="CVE-2021-44228",
    url="https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    fixes=(AdvisoryFix(package="log4j-core", fixed_version="2.17.1"),),
)


def _threat(**overrides: object) -> dict[str, object]:
    payload = ThreatDetectionResult(
        investigation_id="inv-1",
        verdict=Verdict.MALICIOUS,
        severity=SeverityAssessment(score=8.0, level=Severity.HIGH, rationale="corroborated"),
        triage_priority=TriagePriority.HIGH,
        attack_techniques=[
            TechniqueMapping(
                technique_id="T1110",
                name="Brute Force",
                tactics=["Credential Access"],
                rationale="repeated failures",
                event_ids=["e1"],
                citations=[ATTACK_CITATION],
            )
        ],
        signals=[
            DetectionSignal(
                rule_id="brute_force_authentication",
                name="Repeated authentication failures",
                description="Five failures for one principal.",
                weight=5.5,
                event_ids=["e1"],
                technique_ids=["T1110"],
                detail="5 failed authentications",
            )
        ],
        confidence=0.85,
    ).model_dump(mode="json")
    payload.update(overrides)
    return payload


def _assessment(
    *, confirmed: bool = True, exploited: bool = False, record: CveRecord = LOG4SHELL
) -> CveAssessment:
    evidence = (
        [
            ApplicabilityEvidence(
                reason=ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE,
                hostname="web-01",
                product="log4j-core",
                installed_version="2.14.1",
                detail="web-01 runs log4j-core 2.14.1",
            )
        ]
        if confirmed
        else [
            ApplicabilityEvidence(
                reason=ApplicabilityReason.VERSION_UNKNOWN,
                hostname="web-02",
                product="log4j-core",
                detail="web-02 runs log4j-core but the inventory records no version",
            )
        ]
    )
    return CveAssessment(
        record=record,
        applicability=(CveApplicability.CONFIRMED if confirmed else CveApplicability.CANDIDATE),
        evidence=evidence,
        exploit_mapping=(
            ExploitMapping(technique_ids=["T1190"], rationale="named in the evidence")
            if exploited
            else ExploitMapping()
        ),
        citations=[Citation(source_id="nvd", source="NVD", url="https://nvd/CVE-2021-44228")],
        confidence=0.9,
    )


def _dossier(**overrides: object) -> dict[str, object]:
    payload = CveResearchResult(
        investigation_id="inv-1", cves=[_assessment()], confidence=0.9
    ).model_dump(mode="json")
    payload.update(overrides)
    return payload


def _request(**overrides: object) -> RemediationPlanRequest:
    payload: dict[str, object] = {
        "investigation_id": "inv-1",
        "threat_assessment": _threat(),
        "vulnerability_dossier": _dossier(),
        "assets": [{"hostname": "web-01"}],
        "critical_assets": ["web-01"],
    }
    payload.update(overrides)
    return RemediationPlanRequest(**payload)


def _recommender(**overrides: object) -> PatchRecommender:
    payload: dict[str, object] = {"advisories": InMemoryAdvisorySource(advisories=[ADVISORY])}
    payload.update(overrides)
    return PatchRecommender(**payload)  # type: ignore[arg-type]


# --- Nothing is executable, nothing is pre-approved --------------------------


def test_every_recommendation_requires_human_approval() -> None:
    plan = _recommender().recommend(_request()).output

    assert plan.requires_human_approval is True
    assert all(item.requires_human_approval is True for item in plan.recommendations)


def test_every_recommendation_is_created_pending() -> None:
    plan = _recommender().recommend(_request()).output
    assert all(item.approval_status is ApprovalStatus.PENDING for item in plan.recommendations)


def test_the_contract_refuses_a_pre_approved_recommendation() -> None:
    """An agent may propose; only a human may approve (invariant #1)."""
    with pytest.raises(ValidationError, match="always proposed pending"):
        RemediationRecommendation(
            action="Patch it",
            type=RecommendationType.PATCH,
            priority=TriagePriority.HIGH,
            risk=RiskScore(score=8.0, level=Severity.HIGH),
            rationale="because",
            citations=[Citation(source_id="nvd", source="NVD")],
            approval_status=ApprovalStatus.APPROVED,
        )


def test_the_contract_refuses_an_unjustified_recommendation() -> None:
    with pytest.raises(ValidationError, match="carries no rationale"):
        RemediationRecommendation(
            action="Patch it",
            type=RecommendationType.PATCH,
            priority=TriagePriority.HIGH,
            risk=RiskScore(score=8.0, level=Severity.HIGH),
            rationale="   ",
            citations=[Citation(source_id="nvd", source="NVD")],
        )


def test_the_contract_refuses_an_uncited_recommendation() -> None:
    with pytest.raises(ValidationError, match="cites no source"):
        RemediationRecommendation(
            action="Patch it",
            type=RecommendationType.PATCH,
            priority=TriagePriority.HIGH,
            risk=RiskScore(score=8.0, level=Severity.HIGH),
            rationale="because the advisory says so",
        )


def test_a_recommendation_carries_no_field_a_machine_could_run() -> None:
    """The structure itself refuses to become an automation payload."""
    forbidden = {"command", "script", "playbook", "playbook_id", "exec", "run", "payload"}
    assert not forbidden & set(RemediationRecommendation.model_fields)


def test_steps_are_written_for_a_person() -> None:
    plan = _recommender().recommend(_request()).output
    for item in plan.recommendations:
        assert item.steps
        assert all(step[0].isupper() for step in item.steps), item.action


# --- Patch guidance ---------------------------------------------------------


def test_a_confirmed_cve_yields_an_upgrade_naming_the_fixed_version() -> None:
    plan = _recommender().recommend(_request()).output
    patch = next(item for item in plan.recommendations if "CVE-2021-44228" in item.action)

    assert "2.17.1" in patch.action
    assert patch.grounding is RemediationConfidence.VENDOR_SPECIFIC
    assert patch.support.cve_ids == ["CVE-2021-44228"]


def test_without_an_advisory_the_guidance_names_no_version() -> None:
    """A fabricated version number would be worse than no advice: someone deploys it."""
    outcome = PatchRecommender().recommend(_request())
    patch = next(item for item in outcome.output.recommendations if "CVE-" in item.action)

    assert "2.17.1" not in patch.action
    assert patch.grounding is not RemediationConfidence.VENDOR_SPECIFIC
    assert any(item.reason == "advisory_unavailable" for item in outcome.degradations)


def test_an_advisory_outage_does_not_cost_the_recommendation() -> None:
    source = InMemoryAdvisorySource(failures=frozenset({"CVE-2021-44228"}))
    plan = PatchRecommender(advisories=source).recommend(_request()).output
    assert any("CVE-2021-44228" in item.action for item in plan.recommendations)


def test_the_advisory_is_cited_when_it_supplied_the_version() -> None:
    plan = _recommender().recommend(_request()).output
    patch = next(item for item in plan.recommendations if "CVE-2021-44228" in item.action)

    assert any(citation.url == ADVISORY.url for citation in patch.citations), [
        c.url for c in patch.citations
    ]


def test_a_candidate_becomes_a_check_not_a_patch() -> None:
    """Patching software nobody established is present wastes a change window."""
    dossier = CveResearchResult(
        investigation_id="inv-1", candidates=[_assessment(confirmed=False)], confidence=0.5
    ).model_dump(mode="json")
    plan = _recommender().recommend(_request(vulnerability_dossier=dossier)).output
    check = next(item for item in plan.recommendations if "Establish whether" in item.action)

    assert check.type is RecommendationType.OTHER
    assert "version_unknown" in check.rationale or "no version" in check.rationale


def test_a_candidate_is_ranked_below_a_confirmation() -> None:
    dossier = CveResearchResult(
        investigation_id="inv-1",
        cves=[_assessment()],
        candidates=[_assessment(confirmed=False)],
        confidence=0.9,
    ).model_dump(mode="json")
    plan = _recommender().recommend(_request(vulnerability_dossier=dossier)).output
    by_action = {item.action: item for item in plan.recommendations}

    confirmed = next(v for k, v in by_action.items() if "Patch CVE" in k)
    candidate = next(v for k, v in by_action.items() if "Establish whether" in k)
    assert confirmed.risk.score > candidate.risk.score


# --- Behavioral mitigations -------------------------------------------------


def test_observed_techniques_yield_their_catalogued_mitigation() -> None:
    plan = _recommender().recommend(_request()).output
    mitigation = next(
        item for item in plan.recommendations if item.support.technique_ids == ["T1110"]
    )

    assert "authentication" in mitigation.action.lower()
    assert mitigation.support.signal_rule_ids == ["brute_force_authentication"]
    assert mitigation.grounding is RemediationConfidence.CLASS_SPECIFIC


def test_a_mitigation_cites_both_mitre_and_the_technique_mapping() -> None:
    plan = _recommender().recommend(_request()).output
    mitigation = next(
        item for item in plan.recommendations if item.support.technique_ids == ["T1110"]
    )
    urls = {citation.url for citation in mitigation.citations}

    assert any(url and "mitigations" in url for url in urls)
    assert ATTACK_CITATION.url in urls


def test_a_technique_with_no_catalogued_mitigation_is_skipped_not_invented() -> None:
    threat = _threat(
        attack_techniques=[
            TechniqueMapping(technique_id="T9999", name="Unknown").model_dump(mode="json")
        ]
    )
    plan = _recommender().recommend(_request(threat_assessment=threat)).output
    assert all("T9999" not in item.support.technique_ids for item in plan.recommendations)


def test_a_stronger_detection_produces_a_higher_risk_mitigation() -> None:
    """A plan where everything is equally urgent says nothing about what to do first."""
    weak = _threat(
        signals=[
            DetectionSignal(
                rule_id="brute_force_authentication",
                name="Repeated authentication failures",
                description="d",
                weight=2.0,
                event_ids=["e1"],
                technique_ids=["T1110"],
            ).model_dump(mode="json")
        ],
        severity={"score": 2.0, "level": "low", "rationale": "weak", "factors": []},
        verdict="suspicious",
    )
    strong_plan = _recommender().recommend(_request(vulnerability_dossier=None)).output
    weak_plan = (
        _recommender()
        .recommend(_request(threat_assessment=weak, vulnerability_dossier=None, critical_assets=[]))
        .output
    )

    assert strong_plan.recommendations[0].risk.score > weak_plan.recommendations[0].risk.score


def test_two_techniques_sharing_a_mitigation_produce_one_item() -> None:
    """Listing the same job twice makes a plan look longer than the work is."""
    threat = _threat(
        attack_techniques=[
            TechniqueMapping(technique_id="T1110", name="Brute Force").model_dump(mode="json"),
            TechniqueMapping(technique_id="T1078", name="Valid Accounts").model_dump(mode="json"),
        ]
    )
    plan = _recommender().recommend(_request(threat_assessment=threat)).output
    auth_items = [item for item in plan.recommendations if "authentication" in item.action.lower()]

    assert len(auth_items) == 1
    assert set(auth_items[0].support.technique_ids) == {"T1110", "T1078"}


# --- Thin knowledge ---------------------------------------------------------


def test_a_non_benign_verdict_with_nothing_specific_gets_labelled_general_advice() -> None:
    threat = _threat(attack_techniques=[], signals=[])
    outcome = _recommender().recommend(
        _request(threat_assessment=threat, vulnerability_dossier=None)
    )

    (item,) = outcome.output.recommendations
    assert item.grounding is RemediationConfidence.GENERIC
    assert outcome.output.knowledge_limited is True
    assert any(entry.reason == "thin_remediation_knowledge" for entry in outcome.degradations)


def test_generic_advice_is_never_presented_as_a_fix() -> None:
    threat = _threat(attack_techniques=[], signals=[])
    plan = (
        _recommender()
        .recommend(_request(threat_assessment=threat, vulnerability_dossier=None))
        .output
    )

    (item,) = plan.recommendations
    assert "general hardening rather than a fix" in item.rationale
    assert "still required" in (item.expected_impact or "")


def test_a_well_grounded_plan_is_not_flagged_knowledge_limited() -> None:
    assert _recommender().recommend(_request()).output.knowledge_limited is False


# --- Nothing to remediate ---------------------------------------------------


def test_a_benign_investigation_yields_an_explicit_empty_plan() -> None:
    """ "We looked and there is nothing to fix" is a finding, not an absence."""
    threat = _threat(verdict="benign", attack_techniques=[], signals=[])
    plan = (
        _recommender()
        .recommend(_request(threat_assessment=threat, vulnerability_dossier=None))
        .output
    )

    assert plan.is_empty
    assert plan.notes
    assert "nothing to remediate" in plan.notes[0]
    assert plan.overall_risk is not None
    assert plan.overall_risk.score == 0.0


def test_no_upstream_findings_at_all_yields_an_empty_plan() -> None:
    outcome = PatchRecommender().recommend(RemediationPlanRequest(investigation_id="inv-1"))
    assert outcome.output.is_empty
    assert outcome.confidence == 0.0


def test_an_unreadable_section_does_not_break_the_plan() -> None:
    plan = _recommender().recommend(_request(threat_assessment={"nonsense": True})).output
    assert plan.recommendations


# --- Prioritization ---------------------------------------------------------


def test_the_plan_is_ordered_most_urgent_first() -> None:
    plan = _recommender().recommend(_request()).output
    order = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
    positions = [order[item.priority.value] for item in plan.recommendations]

    assert positions == sorted(positions)


def test_the_overall_risk_takes_the_worst_finding() -> None:
    plan = _recommender().recommend(_request()).output
    assert plan.overall_risk is not None
    assert plan.overall_risk.score == max(item.risk.score for item in plan.recommendations)


def test_exploited_findings_are_urgent_regardless_of_score() -> None:
    dossier = CveResearchResult(
        investigation_id="inv-1", cves=[_assessment(exploited=True)], confidence=0.9
    ).model_dump(mode="json")
    plan = _recommender().recommend(_request(vulnerability_dossier=dossier)).output
    patch = next(item for item in plan.recommendations if "CVE-2021-44228" in item.action)

    assert patch.priority is TriagePriority.URGENT


def test_the_plan_is_bounded_and_the_shortfall_declared() -> None:
    techniques = [
        TechniqueMapping(technique_id=technique, name=technique).model_dump(mode="json")
        for technique in ("T1110", "T1027", "T1070", "T1562", "T1071")
    ]
    plan = (
        _recommender(max_recommendations=2)
        .recommend(_request(threat_assessment=_threat(attack_techniques=techniques)))
        .output
    )

    assert len(plan.recommendations) == 2
    assert any("held back" in note for note in plan.notes)


def test_the_highest_priority_is_reported() -> None:
    plan = _recommender().recommend(_request()).output
    assert plan.highest_priority is plan.recommendations[0].priority


# --- Contract and reproducibility -------------------------------------------


def test_the_outcome_carries_the_pinned_prompt_version() -> None:
    outcome = _recommender().recommend(_request())
    assert outcome.agent == "patch_recommender"
    assert outcome.prompt_version == "1.0.0"


def test_tool_calls_stay_inside_the_allow_list() -> None:
    outcome = _recommender().recommend(_request())
    assert {str(call["tool"]) for call in outcome.tool_calls} <= set(ALLOWED_TOOLS)


def test_confidence_reflects_the_section_a_recommendation_rests_on() -> None:
    """CVE research finding nothing must not discredit a behavioral mitigation."""
    empty_dossier = CveResearchResult(investigation_id="inv-1", confidence=0.0).model_dump(
        mode="json"
    )
    with_empty = _recommender().recommend(_request(vulnerability_dossier=empty_dossier)).confidence
    without = _recommender().recommend(_request(vulnerability_dossier=None)).confidence

    assert with_empty == pytest.approx(without)


def test_the_plan_is_reproducible() -> None:
    first = _recommender().recommend(_request()).output
    second = _recommender().recommend(_request()).output
    assert first.model_dump() == second.model_dump()


def test_recommendations_are_addressed_to_the_hosts_involved() -> None:
    plan = _recommender().recommend(_request()).output
    assert all(item.targets for item in plan.recommendations)

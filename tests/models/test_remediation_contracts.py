"""Tests for the remediation contracts.

These guard the shape rules that make an assistive platform stay assistive: no
executable field, no clearable approval flag, no unjustified or uncited advice.
"""

import pytest
from pydantic import ValidationError

from models.enums import ApprovalStatus, RecommendationType, Severity, TriagePriority
from models.remediation import (
    RemediationConfidence,
    RemediationPlan,
    RemediationRecommendation,
    RemediationSupport,
    RiskFactor,
    RiskScore,
)
from models.values import Citation

CITATION = Citation(source_id="nvd", source="NVD", url="https://nvd/CVE-1")


def _recommendation(**overrides: object) -> RemediationRecommendation:
    payload: dict[str, object] = {
        "action": "Patch CVE-1",
        "type": RecommendationType.PATCH,
        "priority": TriagePriority.HIGH,
        "risk": RiskScore(score=7.5, level=Severity.HIGH),
        "rationale": "Confirmed applicable.",
        "citations": [CITATION],
    }
    payload.update(overrides)
    return RemediationRecommendation(**payload)


# --- Nothing executable -----------------------------------------------------


def test_no_field_could_carry_something_a_machine_runs() -> None:
    """A structure that cannot hold a payload cannot be wired to a runner."""
    forbidden = {
        "command",
        "commands",
        "script",
        "playbook",
        "playbook_id",
        "payload",
        "exec",
        "run",
        "automation",
    }
    assert not forbidden & set(RemediationRecommendation.model_fields)


def test_steps_are_plain_instructions() -> None:
    item = _recommendation(steps=["Upgrade the package.", "Restart the service."])
    assert all(isinstance(step, str) for step in item.steps)


# --- Approval cannot be cleared ---------------------------------------------


def test_human_approval_is_not_a_flag_a_caller_can_clear() -> None:
    with pytest.raises(ValidationError):
        _recommendation(requires_human_approval=False)


def test_a_recommendation_cannot_be_created_approved() -> None:
    with pytest.raises(ValidationError, match="always proposed pending"):
        _recommendation(approval_status=ApprovalStatus.APPROVED)


def test_a_recommendation_cannot_be_created_rejected_either() -> None:
    with pytest.raises(ValidationError, match="always proposed pending"):
        _recommendation(approval_status=ApprovalStatus.REJECTED)


def test_a_plan_states_the_guarantee_at_its_own_level() -> None:
    with pytest.raises(ValidationError):
        RemediationPlan(investigation_id="inv-1", requires_human_approval=False)


# --- Justified and sourced --------------------------------------------------


@pytest.mark.parametrize("rationale", ["", "   ", "\n"])
def test_an_unjustified_recommendation_is_refused(rationale: str) -> None:
    with pytest.raises(ValidationError, match="carries no rationale"):
        _recommendation(rationale=rationale)


def test_an_uncited_recommendation_is_refused() -> None:
    """A change request without a source is one an analyst cannot check."""
    with pytest.raises(ValidationError, match="cites no source"):
        _recommendation(citations=[])


# --- Support ----------------------------------------------------------------


def test_empty_support_reports_itself_empty() -> None:
    assert RemediationSupport().is_empty is True


@pytest.mark.parametrize(
    "support",
    [
        RemediationSupport(cve_ids=["CVE-1"]),
        RemediationSupport(technique_ids=["T1110"]),
        RemediationSupport(signal_rule_ids=["brute_force"]),
        RemediationSupport(cwe_ids=["CWE-502"]),
    ],
)
def test_any_reference_makes_support_non_empty(support: RemediationSupport) -> None:
    assert support.is_empty is False


# --- Risk -------------------------------------------------------------------


def test_a_risk_score_is_bounded_to_the_shared_scale() -> None:
    with pytest.raises(ValidationError):
        RiskScore(score=11.0, level=Severity.CRITICAL)


def test_risk_factors_may_be_negative() -> None:
    """A discount is a contribution too, and has to be visible as one."""
    factor = RiskFactor(name="unconfirmed", weight=-2.0)
    assert factor.weight < 0


# --- Plan -------------------------------------------------------------------


def test_an_empty_plan_reports_itself_empty() -> None:
    plan = RemediationPlan(investigation_id="inv-1")

    assert plan.is_empty is True
    assert plan.highest_priority is None
    assert plan.knowledge_limited is False
    assert plan.confidence == 0.0


def test_the_highest_priority_is_the_most_urgent_present() -> None:
    plan = RemediationPlan(
        investigation_id="inv-1",
        recommendations=[
            _recommendation(priority=TriagePriority.LOW),
            _recommendation(priority=TriagePriority.URGENT),
            _recommendation(priority=TriagePriority.MEDIUM),
        ],
    )
    assert plan.highest_priority is TriagePriority.URGENT


def test_grounding_defaults_to_the_weakest_claim() -> None:
    """An unlabelled recommendation should read as generic, not as vendor-specified."""
    assert _recommendation().grounding is RemediationConfidence.GENERIC


def test_contracts_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _recommendation(auto_execute=True)

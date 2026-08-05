"""Tests for the human interrupt gate: pause, resume, redirect, and fail-fast."""

import pytest

from graph.errors import InvalidResumeError, InvestigationNotFoundError
from graph.runtime import InvestigationGraphService
from models.enums import InvestigationStatus


def test_interrupt_pauses_and_surfaces_awaiting_human(service: InvestigationGraphService) -> None:
    result = service.start(investigation_id="inv-1", trigger_source="analyst")
    assert result.awaiting_human is True
    # The paused state is durable: re-reading still reports awaiting.
    again = service.get_state("inv-1")
    assert again.awaiting_human is True
    assert again.status == InvestigationStatus.AWAITING_APPROVAL.value


def test_reject_closes_the_investigation(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(investigation_id="inv-1", decision="reject")
    assert result.status == InvestigationStatus.CLOSED.value
    assert result.awaiting_human is False


def test_redirect_re_enters_triage_then_can_be_approved(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    redirected = service.resume(investigation_id="inv-1", decision="redirect")
    # A redirect rolls back into the pipeline and pauses at the gate again.
    assert redirected.awaiting_human is True
    assert redirected.status == InvestigationStatus.AWAITING_APPROVAL.value

    approved = service.resume(investigation_id="inv-1", decision="approve")
    assert approved.status == InvestigationStatus.CLOSED.value
    # History is retained, not destroyed: the pipeline was traversed twice.
    nodes = [t["node"] for t in approved.node_history]
    assert nodes == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "report",
        "remediation",
        "triage",
        "human_gate",
        "triage",
        "human_gate",
        "close",
    ]


def test_resume_without_pending_gate_fails_fast(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    service.resume(investigation_id="inv-1", decision="approve")  # now closed
    with pytest.raises(InvalidResumeError):
        service.resume(investigation_id="inv-1", decision="approve")


def test_invalid_decision_is_rejected(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    with pytest.raises(InvalidResumeError):
        service.resume(investigation_id="inv-1", decision="frobnicate")


def test_get_state_unknown_investigation_raises(service: InvestigationGraphService) -> None:
    with pytest.raises(InvestigationNotFoundError):
        service.get_state("does-not-exist")


def test_edit_decision_is_treated_as_approval(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(investigation_id="inv-1", decision="edit")
    assert result.status == InvestigationStatus.CLOSED.value

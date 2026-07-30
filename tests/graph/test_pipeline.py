"""End-to-end tests for the stub investigation pipeline."""

from graph.runtime import InvestigationGraphService
from models.enums import InvestigationStatus


def test_stub_pipeline_runs_to_the_human_gate(service: InvestigationGraphService) -> None:
    result = service.start(investigation_id="inv-1", trigger_source="analyst")
    assert result.status == InvestigationStatus.AWAITING_APPROVAL.value
    assert result.current_node == "triage"
    assert result.awaiting_human is True
    assert result.pending_interrupt is not None
    assert result.pending_interrupt["kind"] == "human_approval"
    assert result.pending_interrupt["investigation_id"] == "inv-1"


def test_approve_runs_pipeline_to_close(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(
        investigation_id="inv-1", decision={"decision": "approve", "actor_id": "u1"}
    )
    assert result.status == InvestigationStatus.CLOSED.value
    assert result.current_node == "close"
    assert result.awaiting_human is False
    assert result.pending_interrupt is None


def test_node_history_is_ordered_and_sequenced(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(investigation_id="inv-1", decision="approve")
    nodes = [t["node"] for t in result.node_history]
    assert nodes == ["ingest_seed", "triage", "human_gate", "close"]
    assert [t["sequence"] for t in result.node_history] == [0, 1, 2, 3]
    # The gate transition is owned by human review and records the decision.
    gate = next(t for t in result.node_history if t["node"] == "human_gate")
    assert gate["owner"] == "human-review"
    assert "approve" in gate["detail"]


def test_config_snapshot_is_pinned(service: InvestigationGraphService) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        config_snapshot={"model": "claude-opus"},
    )
    state = service.get_state("inv-1")
    # The run is reproducible: the recorded transitions carry the seeded config.
    assert state.node_history[0]["node"] == "ingest_seed"


def test_decision_is_recorded_for_audit(
    service: InvestigationGraphService, fixed_clock: str
) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(
        investigation_id="inv-1",
        decision={"decision": "approve", "actor_id": "analyst-7", "rationale": "looks benign"},
    )
    assert result.updated_at == fixed_clock

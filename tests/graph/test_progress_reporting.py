"""Tests for per-node progress reporting from the graph runtime.

The callback exists so the backend can persist an agent's output the moment that
agent finishes rather than at the end of the pipeline. Two properties make it
safe to rely on: it reports every node that produced state, in order; and a
callback that raises costs its own report, never the run — the remaining nodes
still have work to do, and their output is worth more than one failed write.
"""

from typing import Any

from graph.runtime import InvestigationGraphService


def _reported(service: InvestigationGraphService, **kwargs: Any) -> list[str]:
    seen: list[str] = []
    service.start(
        investigation_id=kwargs.pop("investigation_id", "inv-1"),
        trigger_source="analyst",
        on_node=lambda node, _update: seen.append(node),
        **kwargs,
    )
    return seen


def test_every_node_that_produced_state_is_reported(
    service: InvestigationGraphService,
) -> None:
    assert _reported(service) == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "report",
        "remediation",
        "triage",
    ]


def test_the_report_carries_the_update_that_node_wrote(
    service: InvestigationGraphService,
) -> None:
    """The callback receives the node's own output, not a re-read of whole state."""
    updates: dict[str, Any] = {}
    service.start(
        investigation_id="inv-1",
        trigger_source="analyst",
        on_node=lambda node, update: updates.__setitem__(node, update),
    )

    assert "threat_assessment" in updates["threat_detection"]["investigation"]
    assert "executive_summary" in updates["report"]["report"]


def test_a_pause_is_not_reported_as_a_node(service: InvestigationGraphService) -> None:
    """The human gate interrupt is a control signal, not state a node produced."""
    assert not [node for node in _reported(service) if node.startswith("__")]


def test_a_raising_callback_does_not_lose_the_run(
    service: InvestigationGraphService,
) -> None:
    """One failed write must not cost every later agent's output."""

    def explode(node: str, _update: Any) -> None:
        raise RuntimeError(f"persisting {node} failed")

    result = service.start(investigation_id="inv-1", trigger_source="analyst", on_node=explode)
    assert result.awaiting_human is True
    assert result.current_node == "triage"


def test_a_run_without_a_callback_behaves_identically(
    service: InvestigationGraphService,
) -> None:
    """Streaming updates rather than invoking must not change the outcome."""
    with_callback = service.start(
        investigation_id="inv-1", trigger_source="analyst", on_node=lambda *_: None
    )
    without = service.start(investigation_id="inv-2", trigger_source="analyst")

    assert with_callback.status == without.status
    assert with_callback.current_node == without.current_node
    assert [entry["node"] for entry in with_callback.node_history] == [
        entry["node"] for entry in without.node_history
    ]


def test_resuming_reports_the_nodes_it_runs(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    seen: list[str] = []
    service.resume(
        investigation_id="inv-1",
        decision="approve",
        on_node=lambda node, _update: seen.append(node),
    )
    assert seen == ["human_gate", "close"]

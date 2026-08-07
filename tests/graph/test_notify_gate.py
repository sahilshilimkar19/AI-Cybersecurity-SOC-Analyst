"""The notify node's reachability — a property of the graph, not of the code.

The strongest form of "no alert before approval" is not a check inside the
dispatcher; it is that there exists no path from START to ``notify`` that does
not traverse the human gate. These tests assert that over the compiled graph, so
a future edge added carelessly fails here rather than in production.

They also pin which decisions alert: only a plain approval. An edit says "change
this first" and a rejection says "these findings are not accepted" — announcing
either to an on-call engineer would be worse than staying quiet.
"""

from typing import Any

import pytest

from graph.nodes import CLOSE, HUMAN_GATE, NOTIFY, TRIAGE, notify, route_after_gate
from graph.registry import node_registry
from graph.runtime import InvestigationGraphService
from graph.state import GraphState, new_state
from models.enums import DecisionType, InvestigationStatus


def _state(decision: str | None) -> Any:
    decisions = [{"decision": decision}] if decision is not None else []
    return {
        "conversation": {"human_decisions": decisions},
        "investigation": {},
        "shared": {},
        "report": {},
    }


# --- Routing ----------------------------------------------------------------


def test_only_an_approval_routes_to_notify() -> None:
    assert route_after_gate(_state(DecisionType.APPROVE.value)) == NOTIFY


@pytest.mark.parametrize("decision", [DecisionType.EDIT.value, DecisionType.REJECT.value])
def test_edit_and_reject_close_without_telling_anyone(decision: str) -> None:
    """Announcing findings an analyst just declined is worse than silence."""
    assert route_after_gate(_state(decision)) == CLOSE


def test_a_redirect_still_re_enters_triage() -> None:
    assert route_after_gate(_state(DecisionType.REDIRECT.value)) == TRIAGE


def test_a_missing_decision_closes_rather_than_alerting() -> None:
    """Fail closed: absence of a decision is not an approval."""
    assert route_after_gate(_state(None)) == CLOSE


def test_an_unrecognized_decision_closes_rather_than_alerting() -> None:
    assert route_after_gate(_state("something-else")) == CLOSE


# --- Reachability -----------------------------------------------------------


def _edges(service: InvestigationGraphService) -> list[tuple[str, str]]:
    graph = service._graph.get_graph()
    return [(edge.source, edge.target) for edge in graph.edges]


def test_notify_has_exactly_one_inbound_edge_and_it_is_the_gate(
    service: InvestigationGraphService,
) -> None:
    """The whole invariant, expressed as a property of the graph's shape."""
    inbound = [source for source, target in _edges(service) if target == NOTIFY]

    assert inbound == [HUMAN_GATE]


def test_no_path_reaches_notify_without_traversing_the_gate(
    service: InvestigationGraphService,
) -> None:
    """A search over the real graph, so a carelessly added edge fails here."""
    edges = _edges(service)
    adjacency: dict[str, list[str]] = {}
    for source, target in edges:
        adjacency.setdefault(source, []).append(target)

    # Walk every path from the entry point, refusing to pass through the gate.
    start = next(source for source, _ in edges if source.startswith("__start__"))
    seen = {start}
    frontier = [start]
    while frontier:
        node = frontier.pop()
        for successor in adjacency.get(node, []):
            if successor == HUMAN_GATE or successor in seen:
                continue
            seen.add(successor)
            frontier.append(successor)

    assert NOTIFY not in seen


def test_notify_leads_onward_to_close(service: InvestigationGraphService) -> None:
    """Alerting is a step in closing an investigation, not a terminus."""
    assert (NOTIFY, CLOSE) in _edges(service)


def test_notify_is_registered_with_an_owner(service: InvestigationGraphService) -> None:
    spec = next(item for item in node_registry() if item.name == NOTIFY)
    assert spec.owner == "graph-runtime"


# --- What the node produces -------------------------------------------------


def _graph_state(**parts: Any) -> GraphState:
    """A real state object, so these tests exercise the shape the node receives."""
    state = new_state(
        investigation_id="inv-1",
        trigger_source="alert",
        config_snapshot={},
        created_at="2026-01-01T00:00:00+00:00",
    )
    for key, value in parts.items():
        state[key].update(value)  # type: ignore[literal-required]
    return state


def test_the_node_prepares_an_alert_but_sends_nothing() -> None:
    """Delivery is a side effect on the world, and side effects are the backend's."""
    update = notify(
        _graph_state(
            investigation={
                "threat_assessment": {
                    "verdict": "malicious",
                    "triage_priority": "urgent",
                    "severity": {"level": "high"},
                }
            },
            shared={"assets": [{"hostname": "web-01"}]},
            report={"executive_summary": "Credentials were guessed."},
        )
    )

    (alert,) = update["notification"]["pending"]
    assert alert["priority"] == "urgent"
    assert alert["severity"] == "high"
    assert alert["verdict"] == "malicious"
    assert "Credentials were guessed." in alert["summary"]
    # No approval id: the node has no idea who approved, and must not guess.
    assert "approval_id" not in alert


def test_affected_hosts_reach_the_alert() -> None:
    update = notify(_graph_state(shared={"assets": [{"hostname": "web-01"}]}))

    highlights = update["notification"]["pending"][0]["highlights"]
    assert any("web-01" in item for item in highlights)


def test_the_alert_states_that_recommendations_are_outstanding() -> None:
    """An on-call reader must not infer from 'we alerted you' that it is handled."""
    update = notify(
        _graph_state(
            investigation={
                "threat_assessment": {"triage_priority": "high", "severity": {"level": "high"}},
                "remediation_plan": {"recommendations": [{"action": "patch"}]},
            }
        )
    )

    highlights = update["notification"]["pending"][0]["highlights"]
    assert any("await human action" in item for item in highlights)


def test_confirmed_cves_and_coverage_gaps_reach_the_alert() -> None:
    update = notify(
        _graph_state(
            investigation={
                "vulnerability_dossier": {"cves": [{"record": {"cve_id": "CVE-2021-44228"}}]},
                "coverage_gaps": ["source unavailable: firewall"],
            }
        )
    )

    highlights = update["notification"]["pending"][0]["highlights"]
    assert any("CVE-2021-44228" in item for item in highlights)
    assert any("coverage gap" in item for item in highlights)


def test_an_alert_for_an_unassessed_investigation_still_has_a_priority() -> None:
    """A missing assessment must not produce an alert with no urgency at all."""
    assert notify(_graph_state())["notification"]["pending"][0]["priority"] == "high"


def test_the_summary_falls_back_when_no_report_was_written() -> None:
    assert notify(_graph_state())["notification"]["pending"][0]["summary"]


# --- End to end through the runtime -----------------------------------------


def test_approving_runs_the_notify_node(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(investigation_id="inv-1", decision="approve")

    assert [entry["node"] for entry in result.node_history][-2:] == [NOTIFY, CLOSE]
    assert result.status == InvestigationStatus.CLOSED.value


@pytest.mark.parametrize("decision", ["reject", "edit"])
def test_declining_never_runs_the_notify_node(
    service: InvestigationGraphService, decision: str
) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    result = service.resume(investigation_id="inv-1", decision=decision)

    assert NOTIFY not in [entry["node"] for entry in result.node_history]
    assert result.status == InvestigationStatus.CLOSED.value


def test_the_prepared_alert_is_reported_to_the_backend(
    service: InvestigationGraphService,
) -> None:
    """The decision route collects it here and dispatches behind the response."""
    service.start(investigation_id="inv-1", trigger_source="analyst")
    seen: dict[str, Any] = {}
    service.resume(
        investigation_id="inv-1",
        decision="approve",
        on_node=lambda node, update: seen.setdefault(node, update),
    )

    assert seen[NOTIFY]["notification"]["pending"]

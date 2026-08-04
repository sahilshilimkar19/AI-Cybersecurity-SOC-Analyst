"""Assemble the investigation graph from the node registry.

Edges encode the deterministic control flow; the human gate branches on the
recorded decision. Sequencing is enforced by edges, not by the nodes (EDS §5).
The compiled graph checkpoints through the supplied checkpointer.

Pipeline:

    START -> ingest_seed -> log_analysis -> threat_detection --benign-----------> report
                                                    \\--suspicious/malicious--> cve_research --^
                                                                                  |
                                     triage -> human_gate --approve--> close -> END
                                       ^           \\--redirect--/

``log_analysis`` establishes the evidence, ``threat_detection`` assesses it,
``cve_research`` runs only when that assessment found something — the verdict
branch from SAD §5 — and ``report`` synthesizes whatever exists into the document
the analyst approves. ``triage`` remains the attachment point for the agents that
follow.

Three properties are load-bearing. The branch skips *work*, never the *gate*:
both arms converge on the report, then triage, then the human interrupt, because
closing an investigation is itself a consequential outcome (invariant #1). The
report is on both arms, so even a benign investigation leaves a record behind.
And sequencing lives in the edges rather than inside the nodes (EDS §5), so no
node decides what runs after it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langgraph.graph import END, START, StateGraph

from graph.nodes import (
    CLOSE,
    CVE_RESEARCH,
    HUMAN_GATE,
    INGEST_SEED,
    LOG_ANALYSIS,
    REPORT,
    THREAT_DETECTION,
    TRIAGE,
    route_after_gate,
    route_after_threat,
)
from graph.registry import node_registry
from graph.state import GraphState

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.types import RetryPolicy


def build_investigation_graph(
    *,
    checkpointer: BaseCheckpointSaver,
    retry_policy: RetryPolicy | None = None,
) -> CompiledStateGraph:
    """Build and compile the investigation graph with the given checkpointer."""
    builder = StateGraph(GraphState)

    for spec in node_registry():
        policy = retry_policy if spec.retriable else None
        # mypy cannot solve LangGraph's contravariant `_Node` protocol union + constrained
        # type var when the action is a stored callable (it resolves fine for a literal def).
        # The call is correct; the node signatures match `_Node[GraphState]`.
        builder.add_node(spec.name, spec.action, retry_policy=policy)  # type: ignore[call-overload]

    builder.add_edge(START, INGEST_SEED)
    builder.add_edge(INGEST_SEED, LOG_ANALYSIS)
    builder.add_edge(LOG_ANALYSIS, THREAT_DETECTION)
    builder.add_conditional_edges(
        THREAT_DETECTION,
        route_after_threat,
        {CVE_RESEARCH: CVE_RESEARCH, REPORT: REPORT},
    )
    builder.add_edge(CVE_RESEARCH, REPORT)
    builder.add_edge(REPORT, TRIAGE)
    builder.add_edge(TRIAGE, HUMAN_GATE)
    builder.add_conditional_edges(
        HUMAN_GATE,
        route_after_gate,
        {CLOSE: CLOSE, TRIAGE: TRIAGE},
    )
    builder.add_edge(CLOSE, END)

    return builder.compile(checkpointer=checkpointer)

"""Orchestration layer — the LangGraph stateful multi-agent graph.

The deterministic control plane around the (later) non-deterministic agents:
nodes, edges, conditional routing, checkpointing, retries, and human-approval
interrupts (governing invariants #1 and #5).

The LangGraph Core sprint ships the skeleton — the shared-state schema and
reducers, a pluggable checkpointer, retry and interrupt scaffolding, node
registry, and a stub pipeline that runs end-to-end with checkpoint/resume and a
first-class human gate. Agent nodes attach to this skeleton in later sprints.

See docs/ENGINEERING_DESIGN_SPEC.md §5 and docs/adr/0004-langgraph-core.md.
"""

from __future__ import annotations

from graph.builder import build_investigation_graph
from graph.checkpointer import CheckpointBackend, build_checkpointer
from graph.errors import (
    GraphConfigurationError,
    GraphError,
    InvalidResumeError,
    InvestigationNotFoundError,
    TransientNodeError,
)
from graph.retry import default_retry_policy
from graph.runtime import (
    CheckpointRef,
    GraphRunResult,
    InvestigationGraphService,
    build_graph_runtime,
)
from graph.state import GraphState, new_state

__all__ = [
    "CheckpointBackend",
    "CheckpointRef",
    "GraphConfigurationError",
    "GraphError",
    "GraphRunResult",
    "GraphState",
    "InvalidResumeError",
    "InvestigationGraphService",
    "InvestigationNotFoundError",
    "TransientNodeError",
    "build_checkpointer",
    "build_graph_runtime",
    "build_investigation_graph",
    "default_retry_policy",
    "new_state",
]

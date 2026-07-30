"""System and stub nodes for the LangGraph Core skeleton.

These are the *deterministic control-plane* nodes only. The agent nodes (Planner,
Log Analyzer, Threat Detector, ...) are empty here and land in their own sprints;
``triage`` is the seam where that pipeline will attach. What this sprint proves is
the machinery: a stub pipeline that runs end-to-end, checkpoints every transition,
pauses at a first-class human interrupt gate, and resumes/redirects on a recorded
decision (governing invariants #1 and #5).

No agent reasoning, no model calls, no external I/O — every node is deterministic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from langgraph.types import interrupt

from graph.state import GraphState, NodeTransition
from models.enums import DecisionType, InvestigationStatus

# Node identifiers. Kept here so routing and the registry share one source of truth.
INGEST_SEED = "ingest_seed"
TRIAGE = "triage"
HUMAN_GATE = "human_gate"
CLOSE = "close"

# Node ownership (SAD §5): system nodes belong to the graph runtime; the approval
# gate belongs to human review.
_OWNER_RUNTIME = "graph-runtime"
_OWNER_HUMAN = "human-review"


def _utcnow() -> str:
    """Wall-clock stamp for ``updated_at`` (monkeypatched in deterministic tests)."""
    return datetime.now(UTC).isoformat()


def _transition(node: str, owner: str, status: str, detail: str = "") -> NodeTransition:
    """Build a transition record; the reducer stamps its ``sequence``."""
    return NodeTransition(sequence=0, node=node, owner=owner, status=status, detail=detail)


def ingest_seed(state: GraphState) -> dict[str, Any]:
    """Seed the investigation from its trigger and mark it in progress."""
    return {
        "status": InvestigationStatus.IN_PROGRESS.value,
        "current_node": INGEST_SEED,
        "updated_at": _utcnow(),
        "node_history": [
            _transition(INGEST_SEED, _OWNER_RUNTIME, "completed", "investigation seeded")
        ],
    }


def triage(state: GraphState) -> dict[str, Any]:
    """Stub control node: the attachment point for the agent pipeline.

    For now it simply advances the investigation to the human approval gate.
    """
    return {
        "status": InvestigationStatus.AWAITING_APPROVAL.value,
        "current_node": TRIAGE,
        "updated_at": _utcnow(),
        "node_history": [_transition(TRIAGE, _OWNER_RUNTIME, "completed", "advanced to gate")],
    }


def human_gate(state: GraphState) -> dict[str, Any]:
    """First-class human approval interrupt.

    Execution pauses here and a resumable checkpoint is persisted; the backend/UI
    sees "awaiting human". On resume the recorded decision is consumed and appended
    to the conversation record for audit. No consequential action node is reachable
    without traversing this gate (invariant #1).
    """
    decision = cast(
        "dict[str, Any]",
        interrupt(
            {
                "kind": "human_approval",
                "investigation_id": state["investigation_id"],
                "reason": "awaiting analyst approval before any consequential action",
            }
        ),
    )
    return {
        "current_node": HUMAN_GATE,
        "updated_at": _utcnow(),
        "conversation": {"human_decisions": [decision]},
        "node_history": [
            _transition(HUMAN_GATE, _OWNER_HUMAN, "completed", f"decision={decision['decision']}")
        ],
    }


def close(state: GraphState) -> dict[str, Any]:
    """Terminal node: finalize and persist the investigation status."""
    return {
        "status": InvestigationStatus.CLOSED.value,
        "current_node": CLOSE,
        "updated_at": _utcnow(),
        "node_history": [_transition(CLOSE, _OWNER_RUNTIME, "completed", "investigation closed")],
    }


def route_after_gate(state: GraphState) -> str:
    """Branch on the recorded human decision (EDS §5 conditional routing).

    approve/edit → close; reject → close; redirect → re-enter ``triage`` (a
    rollback-by-retain redirect that re-runs the pipeline rather than mutating
    history).
    """
    decisions = state["conversation"]["human_decisions"]
    if decisions and decisions[-1].get("decision") == DecisionType.REDIRECT.value:
        return TRIAGE
    return CLOSE

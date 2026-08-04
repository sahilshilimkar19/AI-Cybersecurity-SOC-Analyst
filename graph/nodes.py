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
LOG_ANALYSIS = "log_analysis"
TRIAGE = "triage"
HUMAN_GATE = "human_gate"
CLOSE = "close"

# Node ownership (SAD §5): system nodes belong to the graph runtime; the approval
# gate belongs to human review; agent nodes are owned by their agent.
_OWNER_RUNTIME = "graph-runtime"
_OWNER_HUMAN = "human-review"
_OWNER_LOG_ANALYZER = "log-analyzer"


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


def log_analysis(state: GraphState) -> dict[str, Any]:
    """Normalize and correlate the seeded evidence into a timeline.

    Writes only into its own agent record and the investigation findings; the raw
    evidence it read is left untouched, so what the graph ingested stays
    distinguishable from what analysis concluded.

    A source that failed to collect arrives here as a recorded failure rather than
    an exception, and leaves as a coverage gap — the investigation proceeds with
    what is available (invariant #6).
    """
    from agents.log_analyzer import AGENT_NAME, LogAnalyzer
    from integrations.log_sources import LogFetchFailure
    from models.logs import LogAnalysisRequest, RawLogRecord, TimeWindow

    evidence = state["evidence"]
    window_payload = evidence.get("time_window")
    request = LogAnalysisRequest(
        investigation_id=state["investigation_id"],
        records=[RawLogRecord.model_validate(item) for item in evidence.get("raw_records", [])],
        requested_sources=list(evidence.get("requested_sources", [])),
        time_window=TimeWindow.model_validate(window_payload) if window_payload else None,
    )
    failures = [
        LogFetchFailure(
            source_id=str(item.get("source_id", "")),
            reason=str(item.get("reason", "unknown")),
            detail=str(item.get("detail", "")),
        )
        for item in evidence.get("source_failures", [])
    ]

    outcome = LogAnalyzer().analyze(request, source_failures=failures)
    result = outcome.output

    return {
        "current_node": LOG_ANALYSIS,
        "updated_at": _utcnow(),
        "investigation": {
            "normalized_events": [event.model_dump(mode="json") for event in result.events],
            "timeline": [entry.model_dump(mode="json") for entry in result.timeline],
            "coverage_gaps": [
                f"{gap.kind.value}: {gap.detail}".strip(": ") for gap in result.coverage_gaps
            ],
        },
        "agents": {
            AGENT_NAME: {
                "agent_name": AGENT_NAME,
                "last_output": {
                    "events": len(result.events),
                    "correlations": len(result.correlations),
                    "quarantined": len(result.quarantined),
                    "source_coverage": result.source_coverage,
                    "parse_failure_rate": result.parse_failure_rate,
                    "prompt_version": outcome.prompt_version,
                },
                "confidence": outcome.confidence,
                "retry_count": 0,
                "tool_calls": outcome.tool_calls,
            }
        },
        "node_history": [
            _transition(
                LOG_ANALYSIS,
                _OWNER_LOG_ANALYZER,
                "completed",
                f"{len(result.events)} events, {len(result.correlations)} correlations, "
                f"{len(result.coverage_gaps)} gaps",
            )
        ],
    }


def triage(state: GraphState) -> dict[str, Any]:
    """Stub control node: the attachment point for the remaining agent pipeline.

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

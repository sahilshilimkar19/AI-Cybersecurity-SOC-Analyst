"""The single, typed shared-state object for the investigation graph.

This is the state schema from SAD §4, composed of ownership-scoped sub-states so
that provenance and who-writes-what are unambiguous (EDS §5). LangGraph channels
carry these fields between nodes; nothing passes outside the state.

Reducer semantics (EDS §5 "append-and-checkpoint"):

* ``node_history`` grows append-only and each entry is stamped with a monotonic
  ``sequence`` by the reducer, giving a deterministic, forensic transition log
  without relying on wall-clock time.
* Sub-states (``shared``, ``investigation``, ``report``, ...) merge field-by-field:
  list fields concatenate (append, provenance-preserving), nested mappings merge,
  and scalar fields are overwritten by their owning node. Because each node writes
  only its designated keys, concurrent writers to different keys never contend
  (writer isolation).

This module intentionally does **not** use ``from __future__ import annotations``:
LangGraph resolves the reducer metadata on these annotations at runtime, so the
``Annotated[...]`` markers must be real objects, not strings.
"""

from collections.abc import Mapping
from typing import Annotated, Any, TypedDict

from models.enums import InvestigationStatus

# The state schema version pinned into every run's config snapshot. Bumping it is
# a breaking change to the checkpoint format and requires a migration strategy.
#
# v2 added the ``evidence`` sub-state so raw records enter the graph alongside the
# findings derived from them.
STATE_SCHEMA_VERSION = 2


# --- Reducers ---------------------------------------------------------------


def extend_history(
    current: list["NodeTransition"], incoming: list["NodeTransition"]
) -> list["NodeTransition"]:
    """Append transitions, stamping each new one with a monotonic sequence number."""
    base = list(current or [])
    offset = len(base)
    for index, transition in enumerate(incoming):
        base.append({**transition, "sequence": offset + index})
    return base


def append_list(current: list[Any], incoming: list[Any]) -> list[Any]:
    """Append-only list reducer (provenance-preserving)."""
    return list(current or []) + list(incoming)


def _merge_value(current: Any, incoming: Any) -> Any:
    if isinstance(current, list) and isinstance(incoming, list):
        return current + incoming
    if isinstance(current, Mapping) and isinstance(incoming, Mapping):
        return _merge_mapping(current, incoming)
    return incoming


def _merge_mapping(current: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = dict(current)
    for key, value in incoming.items():
        result[key] = _merge_value(result[key], value) if key in result else value
    return result


def merge_substate(current: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Merge a sub-state update: lists append, nested mappings merge, scalars overwrite."""
    return _merge_mapping(current or {}, incoming or {})


# --- Records ----------------------------------------------------------------


class NodeTransition(TypedDict):
    """One entry in the per-node transition log (EDS §3.3 logging)."""

    sequence: int
    node: str
    owner: str
    status: str
    detail: str


class GraphErrorRecord(TypedDict):
    """A recorded node failure retained in state for forensics (never silent-dropped)."""

    node: str
    error: str
    message: str


# --- Ownership-scoped sub-states (SAD §4) -----------------------------------


class SharedMemory(TypedDict):
    """Cross-agent working context ("blackboard"); append-oriented, all agents write."""

    retrieved_context: list[dict[str, Any]]
    entities: list[dict[str, Any]]
    assets: list[dict[str, Any]]
    working_notes: list[str]


class AgentRecord(TypedDict):
    """Per-agent working record; writer-isolated by agent name."""

    agent_name: str
    last_output: dict[str, Any] | None
    confidence: float | None
    retry_count: int
    tool_calls: list[dict[str, Any]]


class EvidenceState(TypedDict):
    """Raw evidence entering the graph, seeded by the backend at investigation start.

    Held separately from :class:`InvestigationFindings` because these are *inputs* —
    what was collected — while findings are what analysis derived from them.
    """

    raw_records: list[dict[str, Any]]
    requested_sources: list[str]
    source_failures: list[dict[str, Any]]
    time_window: dict[str, Any] | None


class InvestigationFindings(TypedDict):
    """The evidential core, written by the Log/Threat/CVE/Patch agents (later sprints)."""

    normalized_events: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    threat_assessment: dict[str, Any] | None
    vulnerability_dossier: dict[str, Any] | None
    remediation_plan: dict[str, Any] | None
    coverage_gaps: list[str]


class ReportState(TypedDict):
    """Report artifacts, written by the Incident Reporter (later sprint)."""

    executive_summary: str | None
    technical_report: str | None
    citations: list[dict[str, Any]]
    report_status: str | None


class NotificationState(TypedDict):
    """Outbound alerting state, written by the notification service (later sprint)."""

    pending: list[dict[str, Any]]
    sent: list[dict[str, Any]]
    channel_results: list[dict[str, Any]]


class ConversationState(TypedDict):
    """The human-in-the-loop record: messages, decisions, and open questions."""

    messages: list[dict[str, Any]]
    human_decisions: list[dict[str, Any]]
    open_questions: list[str]


# --- The composed graph state ----------------------------------------------


class GraphState(TypedDict):
    """The single typed state object checkpointed at every transition (SAD §4).

    Global control fields are owned by the graph runtime; each sub-state is owned
    by exactly one component and merged by its reducer.
    """

    # Global control envelope (graph runtime).
    schema_version: int
    investigation_id: str
    trigger_source: str
    status: str
    current_node: str
    config_snapshot: dict[str, Any]
    created_at: str
    updated_at: str

    # Append-only control logs.
    node_history: Annotated[list[NodeTransition], extend_history]
    errors: Annotated[list[GraphErrorRecord], append_list]

    # Ownership-scoped sub-states.
    shared: Annotated[SharedMemory, merge_substate]
    agents: Annotated[dict[str, AgentRecord], merge_substate]
    evidence: Annotated[EvidenceState, merge_substate]
    investigation: Annotated[InvestigationFindings, merge_substate]
    report: Annotated[ReportState, merge_substate]
    notification: Annotated[NotificationState, merge_substate]
    conversation: Annotated[ConversationState, merge_substate]


def new_state(
    *,
    investigation_id: str,
    trigger_source: str,
    config_snapshot: Mapping[str, Any],
    created_at: str,
    evidence: Mapping[str, Any] | None = None,
) -> GraphState:
    """Build a fresh, fully-initialized state for a new investigation.

    ``config_snapshot`` is pinned into the state so a run is reproducible even if
    global configuration later drifts (SAD §4 design decision).
    """
    snapshot = dict(config_snapshot)
    snapshot.setdefault("schema_version", STATE_SCHEMA_VERSION)
    return GraphState(
        schema_version=STATE_SCHEMA_VERSION,
        investigation_id=investigation_id,
        trigger_source=trigger_source,
        status=InvestigationStatus.OPEN.value,
        current_node="",
        config_snapshot=snapshot,
        created_at=created_at,
        updated_at=created_at,
        node_history=[],
        errors=[],
        shared=SharedMemory(retrieved_context=[], entities=[], assets=[], working_notes=[]),
        agents={},
        evidence=EvidenceState(
            raw_records=list(dict(evidence or {}).get("raw_records", [])),
            requested_sources=list(dict(evidence or {}).get("requested_sources", [])),
            source_failures=list(dict(evidence or {}).get("source_failures", [])),
            time_window=dict(evidence or {}).get("time_window"),
        ),
        investigation=InvestigationFindings(
            normalized_events=[],
            timeline=[],
            threat_assessment=None,
            vulnerability_dossier=None,
            remediation_plan=None,
            coverage_gaps=[],
        ),
        report=ReportState(
            executive_summary=None, technical_report=None, citations=[], report_status=None
        ),
        notification=NotificationState(pending=[], sent=[], channel_results=[]),
        conversation=ConversationState(messages=[], human_decisions=[], open_questions=[]),
    )

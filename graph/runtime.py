"""The graph's public runtime interface — start, resume, inspect, roll back.

This is the seam the backend calls (EDS §3.3 public interfaces). It wraps the
compiled graph, keying every investigation to a LangGraph ``thread_id`` so its
checkpoints are isolated and resumable. Human decisions are validated here, at the
service boundary, so an invalid resume fails fast before touching the graph.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from config.logging import get_logger
from graph.builder import build_investigation_graph
from graph.checkpointer import build_checkpointer
from graph.errors import InvalidResumeError, InvestigationNotFoundError
from graph.retry import default_retry_policy
from graph.state import new_state
from models.enums import DecisionType

if TYPE_CHECKING:
    from langchain_core.runnables import RunnableConfig
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.types import StateSnapshot

    from config.settings import Settings

_logger = get_logger(__name__)

_VALID_DECISIONS = frozenset(member.value for member in DecisionType)


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class GraphRunResult(BaseModel):
    """The outcome of a start/resume: current status and whether a human is awaited."""

    investigation_id: str
    status: str
    current_node: str
    awaiting_human: bool
    pending_interrupt: dict[str, Any] | None
    node_history: list[dict[str, Any]]
    created_at: str
    updated_at: str


class CheckpointRef(BaseModel):
    """A reference to one checkpoint in an investigation's history."""

    checkpoint_id: str
    next_nodes: tuple[str, ...]
    pending: bool


class InvestigationGraphService:
    """Start, resume, inspect, and roll back investigations on the compiled graph."""

    def __init__(
        self,
        graph: CompiledStateGraph,
        *,
        clock: Callable[[], str] = _utcnow_iso,
    ) -> None:
        self._graph = graph
        self._clock = clock

    @staticmethod
    def _config(investigation_id: str, *, checkpoint_id: str | None = None) -> RunnableConfig:
        configurable: dict[str, Any] = {"thread_id": investigation_id}
        if checkpoint_id is not None:
            configurable["checkpoint_id"] = checkpoint_id
        return {"configurable": configurable}

    def start(
        self,
        *,
        investigation_id: str,
        trigger_source: str,
        config_snapshot: Mapping[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
        assets: Sequence[Mapping[str, Any]] | None = None,
        on_node: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> GraphRunResult:
        """Start a new investigation, running until the human gate or completion.

        ``evidence`` seeds the raw records collected by the backend, which the
        Log Analyzer node then normalizes and correlates. ``assets`` seeds the
        software inventory of the machines involved, which is what lets CVE
        research confirm applicability rather than only suspect it.

        ``on_node`` is called with each node's name and the update it wrote, as
        the run proceeds. It exists so the backend can persist an agent's output
        the moment that agent finishes rather than at the end of the pipeline: an
        investigation that takes a minute should not be invisible for a minute,
        and a run that dies mid-pipeline should leave the work already done behind
        it (invariant #6). A raising callback must not lose the run, so failures
        are recorded and the pipeline continues.
        """
        state = new_state(
            investigation_id=investigation_id,
            trigger_source=trigger_source,
            config_snapshot=config_snapshot or {},
            created_at=self._clock(),
            evidence=evidence,
            assets=assets,
        )
        self._run(state, self._config(investigation_id), on_node)
        return self._result(investigation_id)

    def _run(
        self,
        payload: Any,
        config: RunnableConfig,
        on_node: Callable[[str, dict[str, Any]], None] | None,
    ) -> None:
        """Drive the graph to its next stop, reporting each node as it completes.

        Streaming updates rather than invoking is what makes per-node reporting
        possible; consuming the stream to exhaustion is equivalent to invoking it.
        """
        for chunk in self._graph.stream(payload, config, stream_mode="updates"):
            if on_node is None or not isinstance(chunk, Mapping):
                continue
            for node, update in chunk.items():
                # LangGraph reports a pause as ``__interrupt__``; it is a control
                # signal, not a node that produced state.
                if str(node).startswith("__") or not isinstance(update, Mapping):
                    continue
                self._report_node(str(node), dict(update), on_node)

    @staticmethod
    def _report_node(
        node: str,
        update: dict[str, Any],
        on_node: Callable[[str, dict[str, Any]], None],
    ) -> None:
        try:
            on_node(node, update)
        except Exception as exc:
            # A reporting failure must not lose the run: the remaining nodes still
            # have work to do, and their output is worth more than this callback.
            _logger.error("graph_node_report_failed", node=node, error=str(exc), exc_info=True)

    def resume(
        self,
        *,
        investigation_id: str,
        decision: Mapping[str, Any] | str,
        on_node: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> GraphRunResult:
        """Resume a paused investigation with a recorded human decision."""
        from langgraph.types import Command

        config = self._config(investigation_id)
        snapshot = self._graph.get_state(config)
        if not snapshot.next:
            raise InvalidResumeError("investigation is not awaiting a human decision")
        normalized = self._coerce_decision(decision)
        self._run(Command(resume=normalized), config, on_node)
        return self._result(investigation_id)

    def get_state(self, investigation_id: str) -> GraphRunResult:
        """Return the current state of an investigation."""
        return self._result(investigation_id)

    def raw_state(self, investigation_id: str) -> dict[str, Any]:
        """Return the full checkpointed state.

        :meth:`get_state` returns the control summary the backend and UI need;
        this exposes the complete state object for inspection, replay, and
        forensic review.
        """
        values: dict[str, Any] = self._graph.get_state(self._config(investigation_id)).values or {}
        if not values:
            raise InvestigationNotFoundError(investigation_id)
        return values

    def history(self, investigation_id: str) -> list[CheckpointRef]:
        """Return the investigation's checkpoint history (newest first)."""
        refs: list[CheckpointRef] = []
        for snapshot in self._graph.get_state_history(self._config(investigation_id)):
            checkpoint_id = snapshot.config.get("configurable", {}).get("checkpoint_id")
            if checkpoint_id is None:
                continue
            refs.append(
                CheckpointRef(
                    checkpoint_id=checkpoint_id,
                    next_nodes=tuple(snapshot.next),
                    pending=bool(snapshot.next),
                )
            )
        if not refs:
            raise InvestigationNotFoundError(investigation_id)
        return refs

    def rollback(self, *, investigation_id: str, checkpoint_id: str) -> GraphRunResult:
        """Roll back to a prior checkpoint and re-run forward from it.

        Prior checkpoints are retained, not destroyed (EDS §5 rollback-by-retain).
        """
        known = {ref.checkpoint_id for ref in self.history(investigation_id)}
        if checkpoint_id not in known:
            raise InvalidResumeError(f"unknown checkpoint: {checkpoint_id!r}")
        self._graph.invoke(None, self._config(investigation_id, checkpoint_id=checkpoint_id))
        return self._result(investigation_id)

    def _coerce_decision(self, decision: Mapping[str, Any] | str) -> dict[str, Any]:
        if isinstance(decision, str):
            data: dict[str, Any] = {"decision": decision}
        elif isinstance(decision, Mapping):
            data = dict(decision)
        else:  # pragma: no cover - defensive; typing forbids other inputs
            raise InvalidResumeError("decision must be a mapping or a string")
        value = str(data.get("decision", "")).lower()
        if value not in _VALID_DECISIONS:
            raise InvalidResumeError(f"invalid decision: {value!r}")
        data["decision"] = value
        return data

    def _result(self, investigation_id: str) -> GraphRunResult:
        snapshot = self._graph.get_state(self._config(investigation_id))
        values: dict[str, Any] = snapshot.values or {}
        if not values:
            raise InvestigationNotFoundError(investigation_id)
        pending = self._pending_interrupt(snapshot)
        return GraphRunResult(
            investigation_id=investigation_id,
            status=values.get("status", ""),
            current_node=values.get("current_node", ""),
            awaiting_human=pending is not None,
            pending_interrupt=pending,
            node_history=list(values.get("node_history", [])),
            created_at=values.get("created_at", ""),
            updated_at=values.get("updated_at", ""),
        )

    @staticmethod
    def _pending_interrupt(snapshot: StateSnapshot) -> dict[str, Any] | None:
        for task in snapshot.tasks:
            for pending in task.interrupts:
                value = pending.value
                return dict(value) if isinstance(value, Mapping) else {"value": value}
        return None


def build_graph_runtime(settings: Settings) -> InvestigationGraphService:
    """Compose the checkpointer, retry policy, and graph into a runtime service."""
    checkpointer = build_checkpointer(settings)
    graph = build_investigation_graph(
        checkpointer=checkpointer,
        retry_policy=default_retry_policy(settings),
    )
    return InvestigationGraphService(graph)

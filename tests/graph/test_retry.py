"""Tests for the per-node retry policy.

Only ``TransientNodeError`` is retried; every other error fails fast so it can be
routed to a human gate rather than silently retried (EDS §5).
"""

from operator import add
from typing import Annotated, Any, TypedDict

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from config.settings import Settings
from graph.errors import TransientNodeError
from graph.retry import default_retry_policy


class _RetryState(TypedDict):
    trail: Annotated[list[str], add]


def _fast_policy() -> Any:
    return default_retry_policy(
        Settings(
            graph_retry_initial_seconds=0.001,
            graph_retry_max_seconds=0.005,
            graph_max_retries=3,
        )
    )


def test_default_retry_policy_maps_settings() -> None:
    policy = default_retry_policy(
        Settings(
            graph_retry_initial_seconds=0.25,
            graph_retry_backoff_factor=3.0,
            graph_retry_max_seconds=10.0,
            graph_max_retries=5,
        )
    )
    assert policy.initial_interval == 0.25
    assert policy.backoff_factor == 3.0
    assert policy.max_interval == 10.0
    assert policy.max_attempts == 5
    assert policy.jitter is True
    assert policy.retry_on == (TransientNodeError,)


def _build(action: Any) -> Any:
    builder = StateGraph(_RetryState)
    builder.add_node("run", action, retry_policy=_fast_policy())
    builder.add_edge(START, "run")
    builder.add_edge("run", END)
    return builder.compile(checkpointer=InMemorySaver())


def test_transient_error_is_retried_then_succeeds() -> None:
    calls = {"n": 0}

    def flaky(state: _RetryState) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] < 3:
            raise TransientNodeError("temporary")
        return {"trail": ["ok"]}

    graph = _build(flaky)
    result = graph.invoke({"trail": []}, {"configurable": {"thread_id": "t"}})
    assert calls["n"] == 3
    assert result["trail"] == ["ok"]


def test_non_transient_error_is_not_retried() -> None:
    calls = {"n": 0}

    def boom(state: _RetryState) -> dict[str, Any]:
        calls["n"] += 1
        raise ValueError("permanent")

    graph = _build(boom)
    with pytest.raises(ValueError, match="permanent"):
        graph.invoke({"trail": []}, {"configurable": {"thread_id": "t"}})
    assert calls["n"] == 1

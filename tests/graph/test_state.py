"""Unit tests for the shared-state schema and its reducers."""

from graph.state import (
    STATE_SCHEMA_VERSION,
    NodeTransition,
    append_list,
    extend_history,
    merge_substate,
    new_state,
)
from models.enums import InvestigationStatus


def _tr(node: str) -> NodeTransition:
    return {"sequence": 0, "node": node, "owner": "o", "status": "s", "detail": ""}


def test_extend_history_stamps_monotonic_sequence() -> None:
    first = extend_history([], [_tr("a")])
    assert [t["sequence"] for t in first] == [0]

    second = extend_history(first, [_tr("b"), _tr("c")])
    assert [t["sequence"] for t in second] == [0, 1, 2]
    assert [t["node"] for t in second] == ["a", "b", "c"]


def test_extend_history_is_append_only() -> None:
    original = extend_history([], [_tr("a")])
    extend_history(original, [_tr("b")])
    # The original list is not mutated in place.
    assert [t["node"] for t in original] == ["a"]


def test_append_list_concatenates() -> None:
    assert append_list(["x"], ["y", "z"]) == ["x", "y", "z"]
    assert append_list([], ["a"]) == ["a"]


def test_merge_substate_appends_lists() -> None:
    current = {"entities": [{"id": 1}], "working_notes": ["n1"]}
    update = {"entities": [{"id": 2}], "working_notes": ["n2"]}
    merged = merge_substate(current, update)
    assert merged["entities"] == [{"id": 1}, {"id": 2}]
    assert merged["working_notes"] == ["n1", "n2"]


def test_merge_substate_overwrites_scalars_and_merges_nested() -> None:
    current = {"report_status": "draft", "meta": {"a": 1, "keep": 9}}
    update = {"report_status": "final", "meta": {"a": 2}}
    merged = merge_substate(current, update)
    assert merged["report_status"] == "final"
    assert merged["meta"] == {"a": 2, "keep": 9}


def test_merge_substate_does_not_mutate_inputs() -> None:
    current = {"entities": [{"id": 1}]}
    merge_substate(current, {"entities": [{"id": 2}]})
    assert current == {"entities": [{"id": 1}]}


def test_new_state_is_fully_initialized() -> None:
    state = new_state(
        investigation_id="inv-1",
        trigger_source="analyst",
        config_snapshot={"model": "claude"},
        created_at="2026-01-01T00:00:00+00:00",
    )
    assert state["schema_version"] == STATE_SCHEMA_VERSION
    assert state["investigation_id"] == "inv-1"
    assert state["status"] == InvestigationStatus.OPEN.value
    assert state["current_node"] == ""
    assert state["node_history"] == []
    assert state["errors"] == []
    # Sub-states exist and are empty.
    assert state["shared"] == {
        "retrieved_context": [],
        "entities": [],
        "assets": [],
        "working_notes": [],
    }
    assert state["investigation"]["threat_assessment"] is None
    assert state["conversation"]["human_decisions"] == []


def test_new_state_pins_schema_version_into_config_snapshot() -> None:
    state = new_state(
        investigation_id="inv-1",
        trigger_source="analyst",
        config_snapshot={},
        created_at="2026-01-01T00:00:00+00:00",
    )
    assert state["config_snapshot"]["schema_version"] == STATE_SCHEMA_VERSION
    assert state["created_at"] == state["updated_at"] == "2026-01-01T00:00:00+00:00"

"""Tests for typed tool results and the least-privilege tool registry."""

import pytest

from tools.base import ToolCallLog, ToolRegistry, ToolResult, ToolSpec
from tools.errors import ToolNotPermittedError, ToolNotRegisteredError


def _spec(name: str = "parse_record") -> ToolSpec:
    return ToolSpec(name=name, description="test tool", handler=lambda: None)


def test_a_successful_result_carries_its_value() -> None:
    result = ToolResult.succeed(42)
    assert result.ok
    assert result.unwrap() == 42


def test_a_failed_result_is_named_not_raised() -> None:
    result: ToolResult[int] = ToolResult.fail("parse_record", "unparseable", "line 3")

    assert not result.ok
    assert result.failure is not None
    assert result.failure.tool == "parse_record"
    assert "unparseable" in str(result.failure)


def test_unwrapping_a_failure_raises() -> None:
    result: ToolResult[int] = ToolResult.fail("parse_record", "unparseable")
    with pytest.raises(ValueError, match="no value"):
        result.unwrap()


def test_registering_a_duplicate_name_is_refused() -> None:
    registry = ToolRegistry()
    registry.register(_spec())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_spec())


def test_an_agent_can_invoke_its_allow_listed_tools() -> None:
    registry = ToolRegistry()
    registry.register(_spec())
    registry.grant("log_analyzer", ["parse_record"])

    assert registry.get("log_analyzer", "parse_record").name == "parse_record"
    assert registry.allowed("log_analyzer") == frozenset({"parse_record"})


def test_tools_are_denied_by_default() -> None:
    """An agent with no grant may invoke nothing, even a registered tool."""
    registry = ToolRegistry()
    registry.register(_spec())

    with pytest.raises(ToolNotPermittedError):
        registry.get("threat_detector", "parse_record")


def test_an_agent_cannot_reach_outside_its_allow_list() -> None:
    registry = ToolRegistry()
    registry.register(_spec("parse_record"))
    registry.register(_spec("virustotal_lookup"))
    registry.grant("log_analyzer", ["parse_record"])

    with pytest.raises(ToolNotPermittedError):
        registry.get("log_analyzer", "virustotal_lookup")


def test_granting_an_unknown_tool_fails_fast() -> None:
    registry = ToolRegistry()
    with pytest.raises(ToolNotRegisteredError):
        registry.grant("log_analyzer", ["does_not_exist"])


def test_requesting_an_unknown_tool_fails_fast() -> None:
    registry = ToolRegistry()
    with pytest.raises(ToolNotRegisteredError):
        registry.get("log_analyzer", "does_not_exist")


def test_registry_lists_its_tools() -> None:
    registry = ToolRegistry()
    registry.register(_spec("b_tool"))
    registry.register(_spec("a_tool"))
    assert registry.names() == ["a_tool", "b_tool"]


def test_call_log_records_outcomes() -> None:
    log = ToolCallLog()
    log.record(tool="parse_record", ok=True)
    log.record(tool="parse_record", ok=False, detail="unparseable")

    assert len(log.calls) == 2
    assert len(log.failures()) == 1

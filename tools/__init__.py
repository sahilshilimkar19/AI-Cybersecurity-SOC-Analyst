"""Tools layer — deterministic capabilities agents invoke (EDS §3.7).

Log parsers/normalizers, entity extractors, and correlators, kept separate from
agent reasoning so they are independently unit-testable and their behavior is
reproducible. Tools are bound to agents on a **least-privilege allow-list**, and
operational problems come back as typed failures rather than raised exceptions.

Nothing in this layer infers threats. Tools establish *what happened*; judging
what it means belongs to the agents that consume them.

See docs/ENGINEERING_DESIGN_SPEC.md §3.7 and §4.2.
"""

from __future__ import annotations

from tools.base import ToolCallLog, ToolFailure, ToolRegistry, ToolResult, ToolSpec
from tools.correlation import correlate_events, score_notability
from tools.errors import ToolError, ToolNotPermittedError, ToolNotRegisteredError
from tools.extraction import extract_entities
from tools.parsers import (
    DEFAULT_PARSERS,
    CefParser,
    JsonLogParser,
    KeyValueParser,
    LogParser,
    ParsedRecord,
    SyslogRfc3164Parser,
    SyslogRfc5424Parser,
    WindowsEventParser,
    classify_event_type,
    parse_record,
    parse_timestamp,
)

__all__ = [
    "DEFAULT_PARSERS",
    "CefParser",
    "JsonLogParser",
    "KeyValueParser",
    "LogParser",
    "ParsedRecord",
    "SyslogRfc3164Parser",
    "SyslogRfc5424Parser",
    "ToolCallLog",
    "ToolError",
    "ToolFailure",
    "ToolNotPermittedError",
    "ToolNotRegisteredError",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "WindowsEventParser",
    "classify_event_type",
    "correlate_events",
    "extract_entities",
    "parse_record",
    "parse_timestamp",
    "score_notability",
]

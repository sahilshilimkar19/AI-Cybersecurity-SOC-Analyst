"""Tools layer — deterministic capabilities agents invoke (EDS §3.7).

Log parsers/normalizers, entity and indicator extractors, correlators, detection
heuristics, the ATT&CK catalogue, and the severity scorer — kept separate from
agent reasoning so they are independently unit-testable and their behavior is
reproducible. Tools are bound to agents on a **least-privilege allow-list**, and
operational problems come back as typed failures rather than raised exceptions.

Every tool here is a pure function of its inputs. A detection rule states that a
specific pattern is present in specific events and weighs it; it never decides
what an investigation *is*. Composing signals into a verdict, weighing what could
not be checked, and deciding what a human should be asked belongs to the agents
that consume these tools.

See docs/ENGINEERING_DESIGN_SPEC.md §3.7, §4.2, and §4.3.
"""

from __future__ import annotations

from tools.attack import TECHNIQUES, TechniqueDefinition, known_technique, map_techniques
from tools.base import ToolCallLog, ToolFailure, ToolRegistry, ToolResult, ToolSpec
from tools.correlation import correlate_events, score_notability
from tools.detection import (
    DEFAULT_RULES,
    DetectionContext,
    DetectionRule,
    RuleMatch,
    evaluate_rules,
    signal_from_hostile_indicators,
)
from tools.errors import ToolError, ToolNotPermittedError, ToolNotRegisteredError
from tools.extraction import extract_entities
from tools.iocs import defang, enrichable, extract_iocs, is_internal_address
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
from tools.severity import (
    assess_escalation,
    derive_priority,
    derive_verdict,
    score_severity,
    severity_level,
)

__all__ = [
    "DEFAULT_PARSERS",
    "DEFAULT_RULES",
    "TECHNIQUES",
    "CefParser",
    "DetectionContext",
    "DetectionRule",
    "JsonLogParser",
    "KeyValueParser",
    "LogParser",
    "ParsedRecord",
    "RuleMatch",
    "SyslogRfc3164Parser",
    "SyslogRfc5424Parser",
    "TechniqueDefinition",
    "ToolCallLog",
    "ToolError",
    "ToolFailure",
    "ToolNotPermittedError",
    "ToolNotRegisteredError",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "WindowsEventParser",
    "assess_escalation",
    "classify_event_type",
    "correlate_events",
    "defang",
    "derive_priority",
    "derive_verdict",
    "enrichable",
    "evaluate_rules",
    "extract_entities",
    "extract_iocs",
    "is_internal_address",
    "known_technique",
    "map_techniques",
    "parse_record",
    "parse_timestamp",
    "score_notability",
    "score_severity",
    "severity_level",
    "signal_from_hostile_indicators",
]

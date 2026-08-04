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
from tools.cvss import base_score, interpret, parse_vector
from tools.cwe import WEAKNESSES, WeaknessDefinition, explain, known_weakness, normalize_cwe_id
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
from tools.rendering import escape_cell, fence, render_executive_summary, render_technical_body
from tools.reporting import (
    assemble_timeline,
    citation_numbers,
    collect_affected_assets,
    compile_citations,
    reference_marks,
)
from tools.severity import (
    assess_escalation,
    derive_priority,
    derive_verdict,
    score_severity,
    severity_level,
)
from tools.versions import (
    Version,
    assess_applicability,
    in_vulnerable_range,
    normalize_product,
    parse_version,
    products_match,
)

__all__ = [
    "DEFAULT_PARSERS",
    "DEFAULT_RULES",
    "TECHNIQUES",
    "WEAKNESSES",
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
    "Version",
    "WeaknessDefinition",
    "WindowsEventParser",
    "assemble_timeline",
    "assess_applicability",
    "assess_escalation",
    "base_score",
    "citation_numbers",
    "classify_event_type",
    "collect_affected_assets",
    "compile_citations",
    "correlate_events",
    "defang",
    "derive_priority",
    "derive_verdict",
    "enrichable",
    "escape_cell",
    "evaluate_rules",
    "explain",
    "extract_entities",
    "extract_iocs",
    "fence",
    "in_vulnerable_range",
    "interpret",
    "is_internal_address",
    "known_technique",
    "known_weakness",
    "map_techniques",
    "normalize_cwe_id",
    "normalize_product",
    "parse_record",
    "parse_timestamp",
    "parse_vector",
    "parse_version",
    "products_match",
    "reference_marks",
    "render_executive_summary",
    "render_technical_body",
    "score_notability",
    "score_severity",
    "severity_level",
    "signal_from_hostile_indicators",
]

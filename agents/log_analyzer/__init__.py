"""Log Analyzer agent — normalize and correlate logs into a timeline.

Structures evidence and nothing more: it establishes *what happened*, leaving
*what it means* to the Threat Detector. See docs/ENGINEERING_DESIGN_SPEC.md §4.2.
"""

from __future__ import annotations

from agents.log_analyzer.analyzer import (
    AGENT_NAME,
    ALLOWED_TOOLS,
    DEFAULT_CORRELATION_WINDOW,
    LogAnalyzer,
)

__all__ = ["AGENT_NAME", "ALLOWED_TOOLS", "DEFAULT_CORRELATION_WINDOW", "LogAnalyzer"]

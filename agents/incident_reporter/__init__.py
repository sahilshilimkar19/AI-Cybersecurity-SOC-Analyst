"""Incident Reporter agent — executive and technical incident reports.

Synthesizes every upstream finding into one defensible document, restating only
what the investigation produced and marking every gap rather than omitting it.
See docs/ENGINEERING_DESIGN_SPEC.md §4.5.
"""

from __future__ import annotations

from agents.incident_reporter.reporter import (
    AGENT_NAME,
    ALLOWED_TOOLS,
    LOW_CONFIDENCE_THRESHOLD,
    IncidentReporter,
)

__all__ = ["AGENT_NAME", "ALLOWED_TOOLS", "LOW_CONFIDENCE_THRESHOLD", "IncidentReporter"]

"""Threat Detector agent — verdict, indicators of compromise, ATT&CK mapping, and
severity/triage.

Decides what the Log Analyzer's evidence *means*, keeping every observation
separate from every inference and never asserting a reputation nobody supplied.
See docs/ENGINEERING_DESIGN_SPEC.md §4.3.
"""

from __future__ import annotations

from agents.threat_detector.detector import (
    AGENT_NAME,
    ALLOWED_TOOLS,
    DEFAULT_DETECTION_WINDOW,
    ThreatDetector,
)

__all__ = ["AGENT_NAME", "ALLOWED_TOOLS", "DEFAULT_DETECTION_WINDOW", "ThreatDetector"]

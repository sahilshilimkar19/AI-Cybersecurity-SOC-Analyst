"""Shared agent contracts reused across the specialist agents.

Every agent returns the same envelope — output, calibrated confidence, tool
calls, and any degradation — so the graph, the Evaluator, and the UI can treat
agents interchangeably. See docs/ENGINEERING_DESIGN_SPEC.md §4.
"""

from __future__ import annotations

from agents.shared.contracts import AgentDegradation, AgentOutcome

__all__ = ["AgentDegradation", "AgentOutcome"]

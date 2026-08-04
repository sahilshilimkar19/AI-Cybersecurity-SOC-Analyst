"""Shared agent contracts (EDS §4).

Every agent produces the same envelope: its output, a calibrated confidence, the
tools it called, and any degradation it had to work around. Uniformity here is
what lets the graph, the Evaluator, and the UI treat agents interchangeably
without special-casing each one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class AgentDegradation:
    """Something the agent had to proceed without."""

    reason: str
    detail: str = ""


@dataclass
class AgentOutcome(Generic[T]):
    """An agent's result plus the metadata the platform needs around it.

    ``degradations`` is never merely logged: a degraded run is surfaced so a human
    can weigh the output knowing what was missing (invariant #6).
    """

    agent: str
    output: T
    confidence: float
    prompt_version: str | None = None
    tool_calls: list[dict[str, object]] = field(default_factory=list)
    degradations: list[AgentDegradation] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        """Whether the agent ran without some input it would normally have."""
        return bool(self.degradations)

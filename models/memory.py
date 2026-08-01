"""Contracts for the tiered memory layer (EDS §7).

These are the shapes exchanged with the memory managers: individual entries with
their provenance, read-only knowledge results, related-investigation pointers,
and the materialized context bundle an agent turn is given.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from models.base import DomainModel
from models.enums import MemoryIndexKind


class MemoryTier(StrEnum):
    """The six memory tiers (SAD §5 / EDS §7)."""

    WORKING = "working"
    SESSION = "session"
    CONVERSATION = "conversation"
    LONG_TERM = "long_term"
    KNOWLEDGE = "knowledge"
    INVESTIGATION_HISTORY = "investigation_history"


class MemoryEntry(DomainModel):
    """A single memory value with the provenance of whoever wrote it.

    ``source`` is never optional: an entry that cannot say where it came from
    cannot be cited, and every claim in this system must be traceable.
    """

    key: str
    value: dict[str, Any] = Field(default_factory=dict)
    source: str
    revision: int = 1
    created_at: datetime | None = None


class KnowledgeChunk(DomainModel):
    """A retrieved chunk of curated reference knowledge (read-only to agents)."""

    chunk_id: str
    content: str
    source: str
    score: float | None = None
    index_version: str | None = None


class RelatedInvestigation(DomainModel):
    """A prior investigation surfaced by the recall index ("seen before")."""

    investigation_id: UUID
    kind: MemoryIndexKind
    value: str


class InvestigationOutcome(DomainModel):
    """The institutional record of a closed investigation (long-term memory)."""

    investigation_id: UUID
    status: str
    severity: str | None = None
    verdict: str | None = None
    title: str | None = None
    closed_at: datetime | None = None


class ConversationTurn(DomainModel):
    """One human/system turn carried into an agent's context."""

    author_type: str
    content: str
    created_at: datetime | None = None


class ContextBundle(DomainModel):
    """Everything an agent turn is given, assembled by the memory layer.

    ``degraded_tiers`` names any tier that could not be read. Callers surface
    that rather than pretending the context is complete — degrade, never
    collapse (invariant #6).
    """

    investigation_id: UUID
    working: list[MemoryEntry] = Field(default_factory=list)
    session: list[MemoryEntry] = Field(default_factory=list)
    conversation: list[ConversationTurn] = Field(default_factory=list)
    knowledge: list[KnowledgeChunk] = Field(default_factory=list)
    related_investigations: list[RelatedInvestigation] = Field(default_factory=list)
    summaries: list[str] = Field(default_factory=list)
    estimated_tokens: int = 0
    degraded_tiers: list[MemoryTier] = Field(default_factory=list)

    @property
    def is_degraded(self) -> bool:
        """Whether any tier was unavailable while assembling this context."""
        return bool(self.degraded_tiers)


class MemoryStats(DomainModel):
    """Counters for memory observability (EDS §3.4 metrics)."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    recoveries: int = 0

    @property
    def hit_ratio(self) -> float:
        """Fraction of reads served from the tier; 0.0 when nothing was read."""
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

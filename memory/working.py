"""Working memory — the scratch space for a single node/agent turn (EDS §7).

Lifetime is one turn and it is never shared laterally between nodes: each
executing node gets its own instance. It is bounded by a **token budget** and an
entry cap; when either is exceeded the oldest entries are evicted through the
summarizer, which keeps their identifiers resolvable rather than discarding them.

Working memory is deliberately in-process. It is rebuilt from session memory on
retry (that is its recovery story), so persisting a per-turn scratchpad to a
network store would add cost and a failure mode without buying durability.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memory.summarization import ReferenceSummarizer, estimate_entry_tokens, estimate_tokens
from models.memory import MemoryEntry, MemoryStats

if TYPE_CHECKING:
    from collections.abc import Sequence

    from memory.summarization import Summarizer


class WorkingMemory:
    """Bounded per-turn scratch space with summarizing eviction."""

    def __init__(
        self,
        *,
        token_budget: int,
        max_entries: int,
        summarizer: Summarizer | None = None,
    ) -> None:
        self._token_budget = token_budget
        self._max_entries = max_entries
        self._summarizer: Summarizer = summarizer or ReferenceSummarizer()
        self._entries: dict[str, MemoryEntry] = {}
        self._summaries: list[str] = []
        self._stats = MemoryStats()

    @property
    def stats(self) -> MemoryStats:
        """Read/eviction counters for this turn."""
        return self._stats.model_copy()

    @property
    def summaries(self) -> list[str]:
        """Summaries produced by eviction, oldest first."""
        return list(self._summaries)

    def write(self, key: str, value: dict[str, Any], *, source: str) -> MemoryEntry:
        """Write an entry, then enforce the budget."""
        entry = MemoryEntry(key=key, value=dict(value), source=source)
        self._entries[key] = entry
        self._enforce_budget()
        return entry

    def read(self, key: str) -> MemoryEntry | None:
        """Read an entry, recording a hit or miss."""
        entry = self._entries.get(key)
        if entry is None:
            self._stats.misses += 1
        else:
            self._stats.hits += 1
        return entry

    def entries(self) -> list[MemoryEntry]:
        """Return the retained entries in insertion order."""
        return list(self._entries.values())

    def load(self, entries: Sequence[MemoryEntry]) -> None:
        """Rebuild this scratchpad from session memory (recovery on retry)."""
        for entry in entries:
            self._entries[entry.key] = entry
        self._stats.recoveries += 1
        self._enforce_budget()

    def estimated_tokens(self) -> int:
        """Current estimated token cost of everything retained."""
        entry_tokens = sum(estimate_entry_tokens(entry) for entry in self._entries.values())
        summary_tokens = sum(estimate_tokens(text) for text in self._summaries)
        return entry_tokens + summary_tokens

    def clear(self) -> None:
        """Discard the scratchpad (end of turn)."""
        self._entries.clear()
        self._summaries.clear()

    def _enforce_budget(self) -> None:
        """Evict oldest-first until the entry cap and token budget are satisfied."""
        evicted: list[MemoryEntry] = []

        while len(self._entries) > self._max_entries:
            evicted.append(self._pop_oldest())

        # Keep at least one entry: an empty scratchpad is never the right answer,
        # and a single oversized entry is the caller's to split.
        while self.estimated_tokens() > self._token_budget and len(self._entries) > 1:
            evicted.append(self._pop_oldest())

        if evicted:
            self._stats.evictions += len(evicted)
            summary = self._summarizer.summarize(evicted)
            if summary:
                self._summaries.append(summary)

    def _pop_oldest(self) -> MemoryEntry:
        oldest_key = next(iter(self._entries))
        return self._entries.pop(oldest_key)

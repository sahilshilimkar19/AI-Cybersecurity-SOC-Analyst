"""The summarization hook — working memory's eviction mechanism (EDS §7).

Summarization is **lossless by reference**: a summary never invents content and
never drops an identifier. Evicted entries are replaced by a compact record that
still names every source key, so the raw evidence remains resolvable from the
durable tier. Nothing is destroyed; it is moved behind a reference.

The hook is a :class:`Summarizer` protocol so the model-backed summarizer built
with the Summarizer agent can replace the default without touching callers. The
default implementation here is **deterministic and model-free**, which keeps the
memory layer testable and independent of the AI layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.memory import MemoryEntry

# Characters per token. A deliberately conservative heuristic so the budget is
# enforced without depending on a provider tokenizer; the AI layer swaps in an
# exact count when it lands.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Estimate the token cost of ``text`` (heuristic, never negative)."""
    if not text:
        return 0
    return max(1, (len(text) + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN)


def estimate_entry_tokens(entry: MemoryEntry) -> int:
    """Estimate the token cost of a memory entry, including its key and value."""
    return estimate_tokens(f"{entry.key}:{entry.value}")


class Summarizer(Protocol):
    """Compresses evicted memory entries into a single reference-preserving note."""

    def summarize(self, entries: Sequence[MemoryEntry]) -> str: ...


class ReferenceSummarizer:
    """Deterministic, model-free summarizer.

    Emits a compact note listing every evicted key with its source, so no
    identifier is lost and the full values stay resolvable from durable memory.
    """

    def summarize(self, entries: Sequence[MemoryEntry]) -> str:
        if not entries:
            return ""
        references = ", ".join(f"{entry.key}@{entry.source}" for entry in entries)
        return (
            f"[summarized {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}; "
            f"full values retained in durable session memory] {references}"
        )

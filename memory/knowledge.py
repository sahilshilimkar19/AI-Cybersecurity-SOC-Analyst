"""Knowledge memory — curated reference knowledge, **read-only to agents** (EDS §7).

This tier holds the trusted corpus (CVE data, ATT&CK, detection heuristics,
remediation runbooks). Its separation from investigation data is a **security
boundary, not an optimization**: untrusted, attacker-influenced investigation
input must never be able to mutate the knowledge agents reason from
(invariant #3). The interface therefore exposes retrieval only, and the explicit
write method exists solely to fail loudly if anything ever tries.

The write path — ingestion, chunking, embedding, and index versioning — belongs
to the RAG pipeline and lands in that sprint. Until then the tier reports itself
unavailable and returns no results, so callers mark their context degraded rather
than silently proceeding as though the corpus were empty (invariant #6).
"""

from __future__ import annotations

from typing import Any, Protocol

from config.logging import get_logger
from memory.errors import MemoryAccessError
from models.memory import KnowledgeChunk

_logger = get_logger(__name__)


class KnowledgeMemory(Protocol):
    """Retrieval-only access to curated reference knowledge."""

    @property
    def is_available(self) -> bool: ...
    def search(self, query: str, *, limit: int = 5) -> list[KnowledgeChunk]: ...


class ReadOnlyKnowledgeMemory:
    """Base enforcing that agents can never write to the knowledge tier."""

    def write(self, *_args: Any, **_kwargs: Any) -> None:
        """Always refuses: knowledge is written only by RAG ingestion."""
        raise MemoryAccessError(
            "knowledge memory is read-only to agents; "
            "it is written exclusively by the RAG ingestion pipeline"
        )


class UnavailableKnowledgeMemory(ReadOnlyKnowledgeMemory):
    """Placeholder until the RAG index exists.

    Reports unavailable and returns nothing, so callers degrade explicitly
    instead of mistaking "not built yet" for "nothing relevant found".
    """

    @property
    def is_available(self) -> bool:
        return False

    def search(self, query: str, *, limit: int = 5) -> list[KnowledgeChunk]:
        _logger.info("knowledge_memory_unavailable", query_length=len(query), limit=limit)
        return []


class InMemoryKnowledgeMemory(ReadOnlyKnowledgeMemory):
    """In-process knowledge tier for tests: a fixed corpus, matched literally."""

    def __init__(self, chunks: list[KnowledgeChunk] | None = None) -> None:
        self._chunks = list(chunks or [])

    @property
    def is_available(self) -> bool:
        return True

    def search(self, query: str, *, limit: int = 5) -> list[KnowledgeChunk]:
        needle = query.lower()
        matches = [chunk for chunk in self._chunks if needle in chunk.content.lower()]
        return matches[:limit]

"""The RAG-backed knowledge memory tier.

Sprint 5 defined knowledge memory as read-only to agents and shipped a placeholder
that reported itself unavailable until an index existed. This is that index: the
adapter satisfies the same read-only contract, so the memory layer gains real
grounding without any change to how agents ask for it.

The write path stays refused here exactly as before — knowledge is written only by
RAG ingestion, never by anything processing untrusted investigation input
(invariant #3).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from config.logging import get_logger
from memory.knowledge import ReadOnlyKnowledgeMemory
from models.memory import KnowledgeChunk

if TYPE_CHECKING:
    from models.knowledge import RetrievalFilters
    from rag.service import RagService

_logger = get_logger(__name__)


class RagKnowledgeMemory(ReadOnlyKnowledgeMemory):
    """Knowledge memory served by the RAG index."""

    def __init__(self, service: RagService, *, filters: RetrievalFilters | None = None) -> None:
        self._service = service
        self._filters = filters

    @property
    def is_available(self) -> bool:
        """Available once at least one source has an active index version."""
        return self._service.is_ready

    def search(self, query: str, *, limit: int = 5) -> list[KnowledgeChunk]:
        """Retrieve grounded chunks, carrying their citation ids and index version."""
        result = self._service.retrieve(query, filters=self._filters, top_k=limit)
        return [
            KnowledgeChunk(
                chunk_id=item.chunk.chunk_id,
                content=item.chunk.content,
                source=item.chunk.metadata.source_name,
                score=item.score,
                index_version=result.index_version,
            )
            for item in result.chunks
        ]

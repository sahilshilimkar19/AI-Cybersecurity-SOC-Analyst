"""Citation binding and resolution (EDS §8 citation strategy).

Every retrieved chunk yields a citation that points back to the exact passage
supporting a claim. This is the mechanism behind invariant #4: a security claim
whose citation cannot be resolved is unverified, and the Evaluator rejects it.

Citations use the shared :class:`~models.values.Citation` contract, so what the
binder emits is what the Reporter compiles into a reference list.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from models.values import Citation

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.knowledge import KnowledgeChunkRecord, RetrievedChunk
    from rag.index import VectorStore


def bind_citation(chunk: KnowledgeChunkRecord) -> Citation:
    """Build the citation for a single chunk."""
    metadata = chunk.metadata
    return Citation(
        source_id=metadata.source_id,
        source=metadata.source_name,
        url=metadata.url,
        chunk_id=chunk.chunk_id,
        title=chunk.title,
        trust_tier=metadata.trust_tier,
        published_at=metadata.published_at,
    )


def bind_citations(chunks: Sequence[RetrievedChunk]) -> list[Citation]:
    """Build citations for retrieved chunks, preserving rank order and deduping."""
    citations: list[Citation] = []
    seen: set[str] = set()
    for item in chunks:
        citation = bind_citation(item.chunk)
        key = citation.chunk_id or citation.source_id
        if key in seen:
            continue
        seen.add(key)
        citations.append(citation)
    return citations


class CitationResolver:
    """Resolves a citation back to the passage it points at.

    Retired chunks resolve too: a citation recorded during an earlier retrieval
    must stay verifiable after the corpus is refreshed.
    """

    def __init__(self, store: VectorStore) -> None:
        self._store = store

    def resolve(self, citation: Citation) -> KnowledgeChunkRecord | None:
        """Return the cited chunk, or ``None`` if it cannot be resolved."""
        if not citation.chunk_id:
            return None
        return self._store.get_chunk(citation.chunk_id)

    def is_resolvable(self, citation: Citation) -> bool:
        """Whether the citation points at a passage that still exists."""
        return self.resolve(citation) is not None

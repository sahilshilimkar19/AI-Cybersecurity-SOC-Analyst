"""Hybrid retrieval: dense + keyword + metadata filters (EDS §8 retriever design).

Security questions are usually a mix of the exact and the conceptual — "what is
CVE-2021-44228" and "how does this lateral movement pattern work" — so neither
path alone is sufficient. The keyword path nails identifiers; the dense path
recovers related concepts the analyst did not name; metadata filters bound both
to the relevant slice of the corpus.

Queries can also be expanded from investigation context (assets, IoCs, techniques,
CVEs), which is how an agent retrieves for what it is actually looking at rather
than only for the words it happened to use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from config.logging import get_logger
from models.knowledge import RetrievalFilters
from rag.ranking import fuse, rank

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.knowledge import RetrievedChunk
    from rag.embeddings import EmbeddingProvider
    from rag.index import VectorStore

_logger = get_logger(__name__)


def expand_query(
    query: str,
    *,
    assets: Sequence[str] = (),
    iocs: Sequence[str] = (),
    techniques: Sequence[str] = (),
    cves: Sequence[str] = (),
) -> str:
    """Expand a query with investigation context, preserving the original text."""
    parts = [query.strip(), *assets, *iocs, *techniques, *cves]
    return " ".join(part for part in parts if part)


class HybridRetriever:
    """Runs both retrieval paths, then fuses and ranks the candidates."""

    def __init__(
        self,
        *,
        store: VectorStore,
        embeddings: EmbeddingProvider,
        candidates: int,
        half_life_days: float,
    ) -> None:
        self._store = store
        self._embeddings = embeddings
        self._candidates = candidates
        self._half_life_days = half_life_days

    def retrieve(
        self, query: str, *, filters: RetrievalFilters | None = None
    ) -> list[RetrievedChunk]:
        """Retrieve ranked candidates for a query."""
        active_filters = filters or RetrievalFilters()

        dense = self._store.dense_search(
            self._embeddings.embed(query), filters=active_filters, limit=self._candidates
        )
        keyword = self._store.keyword_search(query, filters=active_filters, limit=self._candidates)

        ranked = rank(fuse(dense, keyword), half_life_days=self._half_life_days)
        _logger.debug(
            "retrieval_candidates",
            dense=len(dense),
            keyword=len(keyword),
            fused=len(ranked),
        )
        return ranked

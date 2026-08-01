"""The RAG module's public face (EDS §3.5 public interfaces).

Two operations: **retrieve grounded context** for a query with filters, and
**ingest/refresh** a source. Agents consume only the first, and only through the
knowledge memory tier, so nothing downstream depends on how retrieval works.

Every result carries the index version it came from and citations that resolve to
the exact passages used — the two properties that make an investigation
reproducible and its claims checkable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from config.logging import get_logger
from memory.summarization import estimate_tokens
from models.knowledge import RetrievalFilters, RetrievalResult
from rag.cache import RetrievalCache, cache_key
from rag.chunking import Chunker
from rag.citations import CitationResolver, bind_citations
from rag.embeddings import build_embedding_provider
from rag.index import InMemoryVectorStore, PgVectorStore
from rag.ingestion import IngestionPipeline
from rag.ranking import take_within_budget
from rag.retriever import HybridRetriever
from rag.sources import DEFAULT_SOURCES, InMemoryFetcher, SourceRegistry

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session

    from config.settings import Settings
    from models.knowledge import IngestionReport
    from rag.embeddings import EmbeddingProvider
    from rag.index import VectorStore
    from rag.sources import DocumentFetcher

_logger = get_logger(__name__)


class RagService:
    """Grounded retrieval and knowledge ingestion."""

    def __init__(
        self,
        *,
        store: VectorStore,
        embeddings: EmbeddingProvider,
        retriever: HybridRetriever,
        pipeline: IngestionPipeline,
        registry: SourceRegistry,
        cache: RetrievalCache,
        top_k: int,
        token_budget: int,
    ) -> None:
        self._store = store
        self._embeddings = embeddings
        self._retriever = retriever
        self._pipeline = pipeline
        self._registry = registry
        self._cache = cache
        self._top_k = top_k
        self._token_budget = token_budget
        self._resolver = CitationResolver(store)

    @property
    def citations(self) -> CitationResolver:
        """Resolver used to verify that a citation still points at a passage."""
        return self._resolver

    @property
    def cache(self) -> RetrievalCache:
        """The retrieval cache, exposed so operators can inspect or clear it."""
        return self._cache

    @property
    def retriever(self) -> HybridRetriever:
        """The hybrid retriever backing this service."""
        return self._retriever

    def index_version_for(self, source_id: str) -> str | None:
        """The index version currently serving a source."""
        return self._store.active_version(source_id)

    def current_index_version(self) -> str | None:
        """The composite version pinning the whole corpus, or ``None`` if empty."""
        return self._current_version()

    @property
    def is_ready(self) -> bool:
        """Whether any source has an active index to retrieve from."""
        return self._current_version() is not None

    def ingest_source(self, source_id: str) -> IngestionReport:
        """Ingest or refresh one source into a new, atomically-activated version."""
        report = self._pipeline.ingest_source(source_id)
        # A corpus change invalidates cached answers keyed to the old version.
        self._cache.clear()
        return report

    def refresh_all(self) -> list[IngestionReport]:
        """Refresh every allow-listed source."""
        reports = self._pipeline.refresh_all()
        self._cache.clear()
        return reports

    def retrieve(
        self,
        query: str,
        *,
        filters: RetrievalFilters | None = None,
        top_k: int | None = None,
    ) -> RetrievalResult:
        """Retrieve grounded, cited context for a query.

        Falls back to the last cached answer (flagged stale) if the index cannot
        be reached, so an investigation degrades rather than stops.
        """
        active_filters = filters or RetrievalFilters()
        version = self._current_version()
        key = cache_key(query, active_filters, version)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        try:
            ranked = self._retriever.retrieve(query, filters=active_filters)
        except Exception:
            _logger.warning("retrieval_failed_using_cache", exc_info=True)
            stale = self._cache.get_stale(key)
            if stale is not None:
                return stale
            # Nothing cached either: return an explicitly empty, stale result
            # rather than raising, so the caller can flag missing grounding.
            return RetrievalResult(query=query, index_version=version, stale=True)

        selected = take_within_budget(
            ranked,
            top_k=top_k or self._top_k,
            token_budget=self._token_budget,
            estimate=estimate_tokens,
        )
        result = RetrievalResult(
            query=query,
            chunks=selected,
            citations=bind_citations(selected),
            index_version=version,
            estimated_tokens=sum(estimate_tokens(item.chunk.content) for item in selected),
        )
        self._cache.set(key, result)
        return result

    def _current_version(self) -> str | None:
        """A composite of every source's active version, pinning the whole corpus."""
        parts = [
            f"{definition.source_id}={self._store.active_version(definition.source_id)}"
            for definition in self._registry.all()
            if self._store.active_version(definition.source_id)
        ]
        return "|".join(parts) if parts else None


def build_rag_service(
    settings: Settings,
    *,
    session_scope: Callable[[], AbstractContextManager[Session]] | None = None,
    fetcher: DocumentFetcher | None = None,
    registry: SourceRegistry | None = None,
) -> RagService:
    """Compose the RAG service from configuration.

    With a ``session_scope`` the corpus lives in PostgreSQL/pgvector; without one
    the service is fully in-process, which is what tests and local runs use.
    """
    active_registry = registry or SourceRegistry(DEFAULT_SOURCES)
    embeddings = build_embedding_provider(settings)
    store: VectorStore = (
        PgVectorStore(session_scope) if session_scope is not None else InMemoryVectorStore()
    )
    chunker = Chunker(
        max_characters=settings.rag_chunk_max_characters,
        overlap_characters=settings.rag_chunk_overlap_characters,
    )
    pipeline = IngestionPipeline(
        registry=active_registry,
        fetcher=fetcher or InMemoryFetcher(),
        chunker=chunker,
        embeddings=embeddings,
        store=store,
    )
    retriever = HybridRetriever(
        store=store,
        embeddings=embeddings,
        candidates=settings.rag_retrieval_candidates,
        half_life_days=settings.rag_freshness_half_life_days,
    )
    return RagService(
        store=store,
        embeddings=embeddings,
        retriever=retriever,
        pipeline=pipeline,
        registry=active_registry,
        cache=RetrievalCache(ttl_seconds=settings.rag_cache_ttl_seconds),
        top_k=settings.rag_retrieval_top_k,
        token_budget=settings.rag_context_token_budget,
    )

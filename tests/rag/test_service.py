"""Tests for the RagService facade: versioning, budget, caching, and degradation."""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from config.settings import Settings
from memory.errors import MemoryAccessError
from memory.service import build_memory_service
from models.knowledge import RetrievalFilters, RetrievalResult, RetrievedChunk
from rag.cache import cache_key
from rag.knowledge_memory import RagKnowledgeMemory
from rag.service import RagService, build_rag_service
from rag.sources import InMemoryFetcher
from tests.rag.conftest import CORPUS


@pytest.fixture
def broken_index(rag: RagService, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make every retrieval attempt fail, as an unreachable index would."""

    def explode(*_args: object, **_kwargs: object) -> list[RetrievedChunk]:
        raise ConnectionError("index unreachable")

    monkeypatch.setattr(rag.retriever, "retrieve", explode)
    yield


def _fresh_result_for(query: str) -> RetrievalResult:
    """A previously-successful result, as it would have been cached."""
    return RetrievalResult(query=query, chunks=[], index_version="seeded")


def test_retrieval_records_the_index_version(rag: RagService) -> None:
    """Reproducibility: a run must be able to say which corpus it saw."""
    result = rag.retrieve("log4j")
    nvd_version = rag.index_version_for("nvd")

    assert result.index_version
    assert nvd_version is not None
    assert nvd_version in result.index_version


def test_service_is_not_ready_before_ingestion() -> None:
    service = build_rag_service(Settings(), fetcher=InMemoryFetcher())
    assert service.is_ready is False
    assert service.current_index_version() is None


def test_service_is_ready_after_ingestion(rag: RagService) -> None:
    assert rag.is_ready is True


def test_results_are_bounded_by_top_k(rag: RagService) -> None:
    result = rag.retrieve("remote code execution", top_k=2)
    assert len(result.chunks) <= 2


def test_results_are_bounded_by_the_token_budget(fetcher: InMemoryFetcher) -> None:
    """Context must fit the budget; a truncated citation is worse than one fewer chunk."""
    from models.enums import KnowledgeSourceKind, SourceTrustTier
    from tests.rag.conftest import make_document

    # Add enough material that the corpus exceeds the smallest allowed budget.
    for index in range(6):
        fetcher.add(
            "internal_runbooks",
            make_document(
                document_id=f"filler-{index}",
                title=f"Containment runbook {index}",
                content=(
                    f"Runbook {index}: isolate the affected host, preserve volatile evidence, "
                    "and escalate to the incident commander before remediation is applied."
                ),
                source_id="internal_runbooks",
                kind=KnowledgeSourceKind.INTERNAL_RUNBOOK,
                trust=SourceTrustTier.INTERNAL,
            ),
        )

    budget = 256
    service = build_rag_service(
        Settings(rag_context_token_budget=budget, rag_retrieval_top_k=8), fetcher=fetcher
    )
    service.refresh_all()

    result = service.retrieve("isolate host preserve evidence escalate incident commander")

    assert result.chunks
    assert len(result.chunks) < 8
    assert result.estimated_tokens <= budget


def test_repeated_queries_are_served_from_cache(rag: RagService) -> None:
    first = rag.retrieve("log4j remote code execution")
    second = rag.retrieve("log4j remote code execution")

    assert first.cached is False
    assert second.cached is True
    assert [c.chunk.chunk_id for c in second.chunks] == [c.chunk.chunk_id for c in first.chunks]


def test_ingestion_invalidates_the_cache(rag: RagService, fetcher: InMemoryFetcher) -> None:
    rag.retrieve("log4j")
    rag.ingest_source("nvd")

    assert rag.retrieve("log4j").cached is False


def test_retrieval_degrades_to_stale_cache_when_the_index_fails(
    rag: RagService, broken_index: None
) -> None:
    """An unreachable index must degrade, not stop the investigation."""
    query = "log4j remote code execution"
    # Seed an already-expired cache entry: the fresh path misses, the index is
    # down, so the stale fallback is the only thing left.
    fresh = _fresh_result_for(query)
    key = cache_key(query, RetrievalFilters(), rag.current_index_version())
    rag.cache.set(key, fresh, now=datetime(2020, 1, 1, tzinfo=UTC))

    degraded = rag.retrieve(query)

    assert degraded.stale is True
    assert degraded.cached is True
    assert [c.chunk.chunk_id for c in degraded.chunks] == [c.chunk.chunk_id for c in fresh.chunks]


def test_retrieval_without_any_cache_returns_an_empty_stale_result(
    rag: RagService, broken_index: None
) -> None:
    result = rag.retrieve("a query never seen before")
    assert result.stale is True
    assert result.is_empty


def test_filters_are_passed_through_to_retrieval(rag: RagService) -> None:
    from models.enums import KnowledgeSourceKind

    result = rag.retrieve(
        "remote code execution",
        filters=RetrievalFilters(source_kinds=[KnowledgeSourceKind.NVD]),
    )
    assert all(item.chunk.metadata.source_kind is KnowledgeSourceKind.NVD for item in result.chunks)


# --- Integration with the memory layer -------------------------------------


def test_rag_backed_knowledge_memory_serves_grounded_chunks(rag: RagService) -> None:
    knowledge = RagKnowledgeMemory(rag)

    assert knowledge.is_available is True
    chunks = knowledge.search("log4j remote code execution", limit=2)
    assert chunks
    assert all(chunk.chunk_id for chunk in chunks)
    assert all(chunk.index_version for chunk in chunks)


def test_rag_backed_knowledge_memory_is_still_read_only(rag: RagService) -> None:
    """The Sprint 5 boundary holds: only ingestion writes knowledge."""
    with pytest.raises(MemoryAccessError):
        RagKnowledgeMemory(rag).write({"content": "injected instruction"})


def test_knowledge_memory_reports_unavailable_before_ingestion() -> None:
    empty = build_rag_service(Settings(), fetcher=InMemoryFetcher())
    assert RagKnowledgeMemory(empty).is_available is False
    assert RagKnowledgeMemory(empty).search("anything") == []


def test_memory_service_context_is_grounded_by_rag(rag: RagService) -> None:
    """The knowledge tier placeholder from Sprint 5 is now backed by a real index."""
    from uuid import uuid4

    service = build_memory_service(Settings(), knowledge=RagKnowledgeMemory(rag))
    bundle = service.materialize_context(uuid4(), query="log4j remote code execution")

    assert bundle.knowledge
    assert bundle.is_degraded is False
    assert all(chunk.chunk_id for chunk in bundle.knowledge)


def test_memory_service_without_rag_still_degrades_explicitly() -> None:
    from uuid import uuid4

    from models.memory import MemoryTier

    service = build_memory_service(Settings())
    bundle = service.materialize_context(uuid4(), query="log4j")

    assert bundle.knowledge == []
    assert MemoryTier.KNOWLEDGE in bundle.degraded_tiers


def test_corpus_documents_all_reach_the_index(rag: RagService) -> None:
    indexed = {
        rag.index_version_for(source_id)
        for source_id in {document.metadata.source_id for document in CORPUS}
    }
    assert None not in indexed

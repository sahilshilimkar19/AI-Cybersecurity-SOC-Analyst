"""Tests for the retrieval cache, degradation fallback, and citation binding."""

from datetime import UTC, datetime, timedelta

from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import (
    ChunkMetadata,
    KnowledgeChunkRecord,
    RetrievalFilters,
    RetrievalResult,
    RetrievedChunk,
)
from rag.cache import RetrievalCache, cache_key
from rag.citations import CitationResolver, bind_citation, bind_citations
from rag.index import InMemoryVectorStore
from rag.service import RagService

NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _record(chunk_id: str = "c1") -> KnowledgeChunkRecord:
    return KnowledgeChunkRecord(
        chunk_id=chunk_id,
        document_id="CVE-2021-44228",
        title="Log4Shell",
        content="body",
        metadata=ChunkMetadata(
            source_kind=KnowledgeSourceKind.NVD,
            source_id="nvd",
            source_name="NVD CVE Feed",
            trust_tier=SourceTrustTier.AUTHORITATIVE,
            published_at=datetime(2021, 12, 10, tzinfo=UTC),
            url="https://example.invalid/cve",
        ),
    )


# --- Cache -----------------------------------------------------------------


def test_cache_key_depends_on_query_filters_and_version() -> None:
    filters = RetrievalFilters()
    base = cache_key("log4j", filters, "v1")

    assert base == cache_key("  LOG4J ", filters, "v1")  # normalized
    assert base != cache_key("log4j", filters, "v2")  # a refresh invalidates
    assert base != cache_key("log4j", RetrievalFilters(cve_ids=["CVE-1"]), "v1")


def test_cache_returns_a_stored_result_flagged_as_cached() -> None:
    cache = RetrievalCache(ttl_seconds=300)
    cache.set("k", RetrievalResult(query="q"), now=NOW)

    cached = cache.get("k", now=NOW + timedelta(seconds=10))
    assert cached is not None
    assert cached.cached is True
    assert cached.stale is False


def test_cache_expires_entries() -> None:
    cache = RetrievalCache(ttl_seconds=60)
    cache.set("k", RetrievalResult(query="q"), now=NOW)
    assert cache.get("k", now=NOW + timedelta(seconds=120)) is None


def test_a_zero_ttl_disables_caching() -> None:
    cache = RetrievalCache(ttl_seconds=0)
    cache.set("k", RetrievalResult(query="q"), now=NOW)
    assert cache.enabled is False
    assert cache.get("k", now=NOW) is None


def test_expired_entries_are_still_available_as_stale() -> None:
    cache = RetrievalCache(ttl_seconds=60)
    cache.set("k", RetrievalResult(query="q"), now=NOW)

    stale = cache.get_stale("k")
    assert stale is not None
    assert stale.stale is True


def test_get_stale_for_an_unknown_key_is_none() -> None:
    assert RetrievalCache(ttl_seconds=60).get_stale("missing") is None


def test_clear_drops_everything() -> None:
    cache = RetrievalCache(ttl_seconds=300)
    cache.set("k", RetrievalResult(query="q"), now=NOW)
    cache.clear()
    assert cache.get("k", now=NOW) is None


# --- Citations -------------------------------------------------------------


def test_citation_carries_everything_needed_to_verify_a_claim() -> None:
    citation = bind_citation(_record())

    assert citation.chunk_id == "c1"
    assert citation.source_id == "nvd"
    assert citation.source == "NVD CVE Feed"
    assert citation.url == "https://example.invalid/cve"
    assert citation.trust_tier is SourceTrustTier.AUTHORITATIVE
    assert citation.published_at is not None


def test_citations_preserve_rank_order_and_deduplicate() -> None:
    chunks = [
        RetrievedChunk(chunk=_record("c1")),
        RetrievedChunk(chunk=_record("c2")),
        RetrievedChunk(chunk=_record("c1")),
    ]
    assert [citation.chunk_id for citation in bind_citations(chunks)] == ["c1", "c2"]


def test_citations_of_nothing_are_empty() -> None:
    assert bind_citations([]) == []


def test_resolver_resolves_a_citation_to_its_passage(rag: RagService) -> None:
    result = rag.retrieve("CVE-2021-44228")
    citation = result.citations[0]

    resolved = rag.citations.resolve(citation)
    assert resolved is not None
    assert resolved.chunk_id == citation.chunk_id
    assert rag.citations.is_resolvable(citation)


def test_every_retrieved_chunk_yields_a_resolvable_citation(rag: RagService) -> None:
    """Invariant #4: grounding that cannot be traced back is not grounding."""
    for query in ("log4j remote code execution", "T1059", "ransomware containment"):
        result = rag.retrieve(query)
        assert len(result.citations) == len(result.chunks)
        assert all(rag.citations.is_resolvable(citation) for citation in result.citations)


def test_a_citation_without_a_chunk_id_does_not_resolve() -> None:
    from models.values import Citation

    resolver = CitationResolver(InMemoryVectorStore())
    assert resolver.resolve(Citation(source_id="nvd", source="NVD")) is None

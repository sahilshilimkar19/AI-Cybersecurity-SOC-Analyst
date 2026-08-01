"""Integration tests for the pgvector-backed knowledge index.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. These prove the real store
behaves like the in-process one: hybrid search, metadata filters, atomic version
swaps, retirement, and citation resolution against PostgreSQL.
"""

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager

import pytest
from sqlalchemy.orm import Session

from config.settings import Settings
from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import RetrievalFilters
from rag.embeddings import DeterministicEmbeddingProvider
from rag.index import PgVectorStore
from rag.service import build_rag_service
from rag.sources import InMemoryFetcher
from tests.rag.conftest import CORPUS, make_document

SessionScope = Callable[[], AbstractContextManager[Session]]


@pytest.fixture
def session_scope(db_session: Session) -> SessionScope:
    """A scope reusing the test transaction, so everything rolls back."""

    @contextmanager
    def scope() -> Iterator[Session]:
        yield db_session
        db_session.flush()

    return scope


@pytest.fixture
def pg_fetcher() -> InMemoryFetcher:
    fetcher = InMemoryFetcher()
    for document in CORPUS:
        fetcher.add(document.metadata.source_id, document)
    return fetcher


@pytest.fixture
def pg_rag(session_scope: SessionScope, pg_fetcher: InMemoryFetcher) -> object:
    service = build_rag_service(
        Settings(rag_retrieval_top_k=3), session_scope=session_scope, fetcher=pg_fetcher
    )
    service.refresh_all()
    return service


def test_chunks_and_embeddings_persist(session_scope: SessionScope, pg_rag: object) -> None:
    store = PgVectorStore(session_scope)
    chunk = store.get_chunk("CVE-2021-44228#0")

    assert chunk is not None
    assert chunk.metadata.cve_id == "CVE-2021-44228"
    assert chunk.metadata.trust_tier is SourceTrustTier.AUTHORITATIVE
    assert chunk.metadata.products == ["log4j-core", "apache-log4j2"]


def test_dense_search_finds_semantically_close_chunks(
    session_scope: SessionScope, pg_rag: object
) -> None:
    store = PgVectorStore(session_scope)
    embedding = DeterministicEmbeddingProvider().embed("apache log4j remote code execution")

    results = store.dense_search(embedding, filters=RetrievalFilters(), limit=5)

    assert results
    assert any(record.metadata.cve_id == "CVE-2021-44228" for record, _ in results)


def test_keyword_search_finds_exact_identifiers(
    session_scope: SessionScope, pg_rag: object
) -> None:
    store = PgVectorStore(session_scope)
    results = store.keyword_search("CVE-2024-3094", filters=RetrievalFilters(), limit=5)

    assert results
    assert results[0][0].metadata.cve_id == "CVE-2024-3094"


def test_metadata_filters_apply_in_sql(session_scope: SessionScope, pg_rag: object) -> None:
    store = PgVectorStore(session_scope)
    results = store.keyword_search(
        "remote code execution",
        filters=RetrievalFilters(source_kinds=[KnowledgeSourceKind.ADVISORY]),
        limit=10,
    )

    assert all(record.metadata.source_kind is KnowledgeSourceKind.ADVISORY for record, _ in results)


def test_end_to_end_retrieval_against_postgres(pg_rag: object) -> None:
    result = pg_rag.retrieve("Log4Shell JNDI remote code execution")  # type: ignore[attr-defined]

    assert result.chunks
    assert result.index_version
    assert len(result.citations) == len(result.chunks)
    assert all(pg_rag.citations.is_resolvable(c) for c in result.citations)  # type: ignore[attr-defined]


def test_refresh_swaps_versions_atomically_and_retires_old_chunks(
    session_scope: SessionScope, pg_fetcher: InMemoryFetcher, pg_rag: object
) -> None:
    store = PgVectorStore(session_scope)
    first_version = store.active_version("nvd")
    assert first_version

    pg_fetcher.add(
        "nvd",
        make_document(
            document_id="CVE-2026-9999",
            title="CVE-2026-9999 new record",
            content="A newly disclosed authentication bypass in an example product.",
            source_id="nvd",
            kind=KnowledgeSourceKind.NVD,
            trust=SourceTrustTier.AUTHORITATIVE,
            cve_id="CVE-2026-9999",
        ),
    )
    report = pg_rag.ingest_source("nvd")  # type: ignore[attr-defined]

    assert report.index_version != first_version
    assert report.chunks_retired > 0
    assert store.active_version("nvd") == report.index_version

    # Retired chunks stay addressable, so older citations still resolve.
    assert store.get_chunk("CVE-2021-44228#0") is not None
    # ...but they no longer surface in new retrievals. Results span sources (the
    # vendor advisory also carries this CVE id), so each must match the version
    # currently active for its own source.
    results = store.keyword_search("CVE-2021-44228", filters=RetrievalFilters(), limit=10)
    assert results
    assert all(
        record.index_version == store.active_version(record.metadata.source_id)
        for record, _ in results
    )


def test_search_excludes_retired_chunks(
    session_scope: SessionScope, pg_fetcher: InMemoryFetcher, pg_rag: object
) -> None:
    store = PgVectorStore(session_scope)
    pg_fetcher.add(
        "mitre_attack",
        make_document(
            document_id="T1078",
            title="T1078 Valid Accounts",
            content="Adversaries obtain and abuse credentials of existing accounts.",
            source_id="mitre_attack",
            kind=KnowledgeSourceKind.MITRE_ATTACK,
            trust=SourceTrustTier.AUTHORITATIVE,
            technique_id="T1078",
        ),
    )
    pg_rag.ingest_source("mitre_attack")  # type: ignore[attr-defined]

    results = store.keyword_search("interpreter", filters=RetrievalFilters(), limit=10)
    assert results
    assert all(
        record.index_version == store.active_version(record.metadata.source_id)
        for record, _ in results
    )

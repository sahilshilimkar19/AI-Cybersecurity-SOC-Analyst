"""Tests for the ingestion pipeline: dedupe, versioning, and atomic swaps."""

from collections.abc import Sequence

import pytest

from config.settings import Settings
from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import SourceDocument
from rag.chunking import Chunker
from rag.embeddings import DeterministicEmbeddingProvider
from rag.errors import UntrustedSourceError
from rag.index import InMemoryVectorStore
from rag.ingestion import IngestionPipeline, build_index_version
from rag.sources import InMemoryFetcher, SourceDefinition, SourceRegistry
from tests.rag.conftest import CORPUS, make_document


def build_pipeline(fetcher: InMemoryFetcher, store: InMemoryVectorStore) -> IngestionPipeline:
    settings = Settings()
    return IngestionPipeline(
        registry=SourceRegistry(),
        fetcher=fetcher,
        chunker=Chunker(
            max_characters=settings.rag_chunk_max_characters,
            overlap_characters=settings.rag_chunk_overlap_characters,
        ),
        embeddings=DeterministicEmbeddingProvider(),
        store=store,
    )


def test_ingestion_indexes_documents_and_reports_counts(
    fetcher: InMemoryFetcher,
) -> None:
    store = InMemoryVectorStore()
    report = build_pipeline(fetcher, store).ingest_source("nvd")

    assert report.documents_fetched == 2
    assert report.documents_ingested == 2
    assert report.chunks_indexed >= 2
    assert report.failed is False
    assert store.active_version("nvd") == report.index_version


def test_identical_documents_are_deduplicated(fetcher: InMemoryFetcher) -> None:
    fetcher.add("nvd", CORPUS[0])  # exact duplicate of an existing record
    report = build_pipeline(fetcher, InMemoryVectorStore()).ingest_source("nvd")

    assert report.documents_fetched == 3
    assert report.documents_ingested == 2
    assert report.duplicates_skipped == 1


def test_index_version_is_stable_for_unchanged_content() -> None:
    version = build_index_version("nvd", "model-a", ["alpha", "beta"])
    assert version == build_index_version("nvd", "model-a", ["beta", "alpha"])
    assert version.startswith("nvd-")


def test_index_version_changes_with_content_or_model() -> None:
    base = build_index_version("nvd", "model-a", ["alpha"])
    assert base != build_index_version("nvd", "model-a", ["alpha", "beta"])
    # A new embedding model means a new index version, never a mixed corpus.
    assert base != build_index_version("nvd", "model-b", ["alpha"])


def test_reingesting_unchanged_content_keeps_the_same_version(
    fetcher: InMemoryFetcher,
) -> None:
    store = InMemoryVectorStore()
    pipeline = build_pipeline(fetcher, store)

    first = pipeline.ingest_source("nvd")
    second = pipeline.ingest_source("nvd")

    assert first.index_version == second.index_version
    assert second.chunks_retired == 0


def test_refresh_with_new_content_swaps_the_version_and_retires_the_old(
    fetcher: InMemoryFetcher,
) -> None:
    store = InMemoryVectorStore()
    pipeline = build_pipeline(fetcher, store)
    first = pipeline.ingest_source("nvd")

    fetcher.add(
        "nvd",
        make_document(
            document_id="CVE-2026-0001",
            title="CVE-2026-0001 new issue",
            content="A newly disclosed remote code execution issue in an example service.",
            source_id="nvd",
            kind=KnowledgeSourceKind.NVD,
            trust=SourceTrustTier.AUTHORITATIVE,
            cve_id="CVE-2026-0001",
        ),
    )
    second = pipeline.ingest_source("nvd")

    assert second.index_version != first.index_version
    assert second.chunks_retired > 0
    assert store.active_version("nvd") == second.index_version


def test_retired_chunks_remain_addressable_for_citations(
    fetcher: InMemoryFetcher,
) -> None:
    store = InMemoryVectorStore()
    pipeline = build_pipeline(fetcher, store)
    pipeline.ingest_source("nvd")
    original_chunk_id = "CVE-2021-44228#0"

    fetcher.add(
        "nvd",
        make_document(
            document_id="CVE-2026-0002",
            title="Another record",
            content="Another distinct advisory body for version change.",
            source_id="nvd",
            kind=KnowledgeSourceKind.NVD,
            trust=SourceTrustTier.AUTHORITATIVE,
        ),
    )
    pipeline.ingest_source("nvd")

    # A citation recorded before the refresh must still resolve.
    assert store.get_chunk(original_chunk_id) is not None


def test_documents_claiming_another_source_are_refused() -> None:
    fetcher = InMemoryFetcher()
    # A document fetched for the runbook source but claiming to be from NVD.
    fetcher.add("internal_runbooks", CORPUS[0])

    with pytest.raises(UntrustedSourceError):
        build_pipeline(fetcher, InMemoryVectorStore()).ingest_source("internal_runbooks")


def test_a_source_that_is_not_allow_listed_cannot_be_ingested() -> None:
    with pytest.raises(UntrustedSourceError):
        build_pipeline(InMemoryFetcher(), InMemoryVectorStore()).ingest_source("random-blog")


def test_fetch_failure_is_isolated_and_reported(fetcher: InMemoryFetcher) -> None:
    store = InMemoryVectorStore()
    pipeline = build_pipeline(fetcher, store)
    pipeline.ingest_source("nvd")
    healthy_version = store.active_version("nvd")

    class BrokenFetcher(InMemoryFetcher):
        def fetch(self, definition: SourceDefinition) -> Sequence[SourceDocument]:
            raise ConnectionError("feed unreachable")

    broken = build_pipeline(BrokenFetcher(), store)
    report = broken.ingest_source("nvd")

    assert report.failed is True
    assert "unreachable" in (report.error or "")
    # The previously active version keeps serving.
    assert store.active_version("nvd") == healthy_version


def test_refresh_all_covers_every_allow_listed_source(fetcher: InMemoryFetcher) -> None:
    reports = build_pipeline(fetcher, InMemoryVectorStore()).refresh_all()
    assert {report.source_id for report in reports} == {
        "nvd",
        "mitre_attack",
        "vendor_advisories",
        "internal_runbooks",
    }
    assert all(report.failed is False for report in reports)

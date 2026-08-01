"""The ingestion pipeline: fetch → clean → dedupe → chunk → embed → index (EDS §8).

Each run builds a **new index version** for one source and swaps it in atomically,
so queries always see a complete corpus rather than a half-rebuilt one. Superseded
chunks are retired rather than deleted, keeping earlier retrievals reproducible.

Failures are isolated per source: one unreachable feed degrades exactly one slice
of knowledge and leaves the previously active version serving (invariant #6).
Documents from sources that are not allow-listed are refused outright — untrusted
provenance never enters the corpus agents reason from (invariant #3).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from config.logging import get_logger
from models.knowledge import IngestionReport
from rag.chunking import clean_text
from rag.errors import UntrustedSourceError
from rag.index import EmbeddedChunk

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.knowledge import SourceDocument
    from rag.chunking import Chunker
    from rag.embeddings import EmbeddingProvider
    from rag.index import VectorStore
    from rag.sources import DocumentFetcher, SourceDefinition, SourceRegistry

_logger = get_logger(__name__)


def build_index_version(source_id: str, embedding_model: str, documents: Sequence[str]) -> str:
    """Derive a deterministic index version from the model and the corpus snapshot.

    Version identity is ``(embedding model, source content)``: re-ingesting
    unchanged documents with the same model yields the same version, so
    reproducibility is a property of the data rather than of a clock.
    """
    digest = hashlib.sha256()
    digest.update(embedding_model.encode("utf-8"))
    for content in sorted(documents):
        digest.update(content.encode("utf-8"))
    return f"{source_id}-{digest.hexdigest()[:16]}"


class IngestionPipeline:
    """Builds and activates index versions for allow-listed sources."""

    def __init__(
        self,
        *,
        registry: SourceRegistry,
        fetcher: DocumentFetcher,
        chunker: Chunker,
        embeddings: EmbeddingProvider,
        store: VectorStore,
    ) -> None:
        self._registry = registry
        self._fetcher = fetcher
        self._chunker = chunker
        self._embeddings = embeddings
        self._store = store

    def ingest_source(self, source_id: str) -> IngestionReport:
        """Ingest one source into a fresh index version and activate it."""
        definition = self._registry.get(source_id)
        try:
            documents = list(self._fetcher.fetch(definition))
        except Exception as exc:
            # Isolate the failure: the previously active version keeps serving.
            _logger.warning("source_fetch_failed", source_id=source_id, exc_info=True)
            return IngestionReport(
                source_id=source_id,
                index_version=self._store.active_version(source_id) or "",
                failed=True,
                error=str(exc),
            )

        unique, duplicates = self._deduplicate(definition, documents)
        version = build_index_version(
            source_id, self._embeddings.model, [document.content for document in unique]
        )

        chunks = [chunk for document in unique for chunk in self._chunker.chunk(document)]
        embedded = [
            EmbeddedChunk(
                **chunk.model_dump(),
                embedding=vector,
            )
            for chunk, vector in zip(
                chunks,
                self._embeddings.embed_batch([chunk.content for chunk in chunks]),
                strict=True,
            )
        ]

        if hasattr(self._store, "record_version"):
            self._store.record_version(
                source_id=source_id,
                version=version,
                embedding_model=self._embeddings.model,
                embedding_dimensions=self._embeddings.dimensions,
                document_count=len(unique),
                chunk_count=len(embedded),
            )

        self._store.add_chunks(embedded, index_version=version)
        retired = self._store.activate_version(source_id, version)

        _logger.info(
            "source_ingested",
            source_id=source_id,
            index_version=version,
            documents=len(unique),
            chunks=len(embedded),
            retired=retired,
        )
        return IngestionReport(
            source_id=source_id,
            index_version=version,
            documents_fetched=len(documents),
            documents_ingested=len(unique),
            duplicates_skipped=duplicates,
            chunks_indexed=len(embedded),
            chunks_retired=retired,
        )

    def refresh_all(self) -> list[IngestionReport]:
        """Refresh every allow-listed source, isolating per-source failures."""
        return [self.ingest_source(definition.source_id) for definition in self._registry.all()]

    def _deduplicate(
        self, definition: SourceDefinition, documents: Sequence[SourceDocument]
    ) -> tuple[list[SourceDocument], int]:
        """Drop repeats by content digest, refusing anything not allow-listed."""
        seen: set[str] = set()
        unique: list[SourceDocument] = []
        duplicates = 0

        for document in documents:
            if document.metadata.source_id != definition.source_id:
                raise UntrustedSourceError(
                    f"document {document.document_id!r} claims source "
                    f"{document.metadata.source_id!r} but was fetched for "
                    f"{definition.source_id!r}"
                )
            digest = hashlib.sha256(clean_text(document.content).encode("utf-8")).hexdigest()
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            unique.append(document)

        return unique, duplicates

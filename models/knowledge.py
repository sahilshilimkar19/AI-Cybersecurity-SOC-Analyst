"""Contracts for the RAG knowledge pipeline (EDS §8).

The shapes flowing through ingestion (source document → chunk → indexed record)
and retrieval (query → ranked, cited context). Everything retrieved carries the
identifiers needed to cite it: a chunk that cannot be traced to a source is not
grounding, it is just text (invariant #4).

Citations reuse the shared :class:`~models.values.Citation` contract, so what the
binder emits is exactly what the Reporter compiles into a reference list.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from models.base import DomainModel
from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.values import Citation


class ChunkMetadata(DomainModel):
    """Filtering, freshness, and citation metadata carried by every chunk.

    The identifier fields drive the keyword path and metadata filters, which is
    what makes exact queries ("CVE-2021-44228") precise rather than merely similar.
    """

    source_kind: KnowledgeSourceKind
    source_id: str
    source_name: str
    trust_tier: SourceTrustTier
    source_version: str | None = None
    published_at: datetime | None = None
    updated_at: datetime | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    technique_id: str | None = None
    products: list[str] = Field(default_factory=list)
    url: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class SourceDocument(DomainModel):
    """A raw document fetched from a knowledge source, before chunking."""

    document_id: str
    title: str
    content: str
    metadata: ChunkMetadata


class KnowledgeChunkRecord(DomainModel):
    """A chunk ready to be indexed, or read back from the index."""

    chunk_id: str
    document_id: str
    title: str | None = None
    content: str
    metadata: ChunkMetadata
    ordinal: int = 0
    # Set when a long document was split, linking a part back to its whole so the
    # full context stays resolvable.
    parent_chunk_id: str | None = None
    index_version: str | None = None


class RetrievalFilters(DomainModel):
    """Metadata filters narrowing a retrieval to the relevant slice of the corpus."""

    source_kinds: list[KnowledgeSourceKind] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    published_after: datetime | None = None
    minimum_trust: SourceTrustTier | None = None

    def is_empty(self) -> bool:
        """Whether this filter set constrains anything at all."""
        return not (
            self.source_kinds
            or self.cve_ids
            or self.technique_ids
            or self.products
            or self.published_after
            or self.minimum_trust
        )


class RetrievedChunk(DomainModel):
    """A retrieved chunk with the scores that earned it its place."""

    chunk: KnowledgeChunkRecord
    dense_score: float = 0.0
    keyword_score: float = 0.0
    freshness_weight: float = 1.0
    trust_weight: float = 1.0
    score: float = 0.0
    # Which retrieval paths surfaced this chunk — useful for debugging recall.
    matched_by: list[str] = Field(default_factory=list)

    @property
    def citation_id(self) -> str:
        """The stable identifier a claim cites."""
        return self.chunk.chunk_id


class RetrievalResult(DomainModel):
    """Grounded context for one query, with everything needed to reproduce it.

    ``index_version`` is recorded so an investigation can be replayed against the
    exact corpus it originally saw, and ``stale`` marks results served from cache
    while the index was unreachable — degraded, but never silently so.
    """

    query: str
    chunks: list[RetrievedChunk] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    index_version: str | None = None
    estimated_tokens: int = 0
    stale: bool = False
    cached: bool = False

    @property
    def is_empty(self) -> bool:
        """Whether retrieval found nothing to ground on."""
        return not self.chunks


class IngestionReport(DomainModel):
    """The outcome of ingesting or refreshing one source."""

    source_id: str
    index_version: str
    documents_fetched: int = 0
    documents_ingested: int = 0
    duplicates_skipped: int = 0
    chunks_indexed: int = 0
    chunks_retired: int = 0
    failed: bool = False
    error: str | None = None

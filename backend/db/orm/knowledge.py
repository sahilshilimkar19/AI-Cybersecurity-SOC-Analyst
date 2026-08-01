"""ORM models backing the RAG knowledge index (EDS §8).

``knowledge_chunks`` holds the corpus: chunk text, its pinned embedding, and the
metadata that drives filtering, freshness weighting, and citation. Chunk metadata
is flattened into columns rather than stored as a blob so the filters that make
security retrieval precise (CVE id, technique, product, publication date) are
indexable — and because ``metadata`` is reserved by SQLAlchemy's declarative API.

``knowledge_index_versions`` tracks each source's index versions. Refresh builds a
new version and swaps it in atomically; superseded chunks are **retired, not
mutated**, so an investigation can still be replayed against the corpus it
originally saw.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from models.enums import IndexStatus, KnowledgeSourceKind, SourceTrustTier
from rag.embeddings import EMBEDDING_DIMENSIONS


class KnowledgeChunk(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One indexed chunk of curated reference knowledge."""

    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        UniqueConstraint(
            "chunk_id", "index_version", name="uq_knowledge_chunks_chunk_id_index_version"
        ),
        Index("ix_knowledge_chunks_source_version", "source_id", "index_version"),
        Index("ix_knowledge_chunks_cve_id", "cve_id"),
        Index("ix_knowledge_chunks_technique_id", "technique_id"),
        Index("ix_knowledge_chunks_retired_at", "retired_at"),
    )

    chunk_id: Mapped[str] = mapped_column(String(255))
    document_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIMENSIONS))

    # --- Flattened chunk metadata (filtering, freshness, citation) ---
    source_kind: Mapped[KnowledgeSourceKind] = mapped_column(
        str_enum_column(KnowledgeSourceKind, "knowledge_source_kind")
    )
    source_id: Mapped[str] = mapped_column(String(128))
    source_name: Mapped[str] = mapped_column(String(255))
    trust_tier: Mapped[SourceTrustTier] = mapped_column(
        str_enum_column(SourceTrustTier, "source_trust_tier")
    )
    source_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    products: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    ordinal: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parent_chunk_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    index_version: Mapped[str] = mapped_column(String(128))
    # Set when a refresh supersedes this chunk. Retired chunks stay readable so
    # prior retrievals remain reproducible.
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class KnowledgeIndexVersion(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One version of one source's index, pinned to an embedding model."""

    __tablename__ = "knowledge_index_versions"
    __table_args__ = (
        UniqueConstraint(
            "source_id", "version", name="uq_knowledge_index_versions_source_id_version"
        ),
        Index("ix_knowledge_index_versions_source_status", "source_id", "status"),
    )

    source_id: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(128))
    embedding_model: Mapped[str] = mapped_column(String(255))
    embedding_dimensions: Mapped[int] = mapped_column(Integer)
    status: Mapped[IndexStatus] = mapped_column(
        str_enum_column(IndexStatus, "index_status"), default=IndexStatus.BUILDING
    )
    document_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

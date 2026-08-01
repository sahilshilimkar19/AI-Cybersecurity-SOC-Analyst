"""The knowledge index: a pluggable vector store (EDS §8, SAD §6).

pgvector is the default store, behind a protocol so a dedicated vector database
can replace it at scale without touching ingestion, retrieval, or ranking. An
in-process store implements the same protocol so the pipeline is fully
exercisable without a database.

Two rules hold in every implementation:

* **Versions are swapped atomically per source.** A refresh builds a new version
  alongside the live one and flips it in one step; a half-built index is never
  the one being queried.
* **Superseded chunks are retired, not deleted.** A retrieval that recorded an
  index version can still be replayed against exactly what it saw.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast

from config.logging import get_logger
from models.enums import IndexStatus, SourceTrustTier
from models.knowledge import ChunkMetadata, KnowledgeChunkRecord, RetrievalFilters
from rag.embeddings import cosine_similarity, tokenize

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from contextlib import AbstractContextManager

    from sqlalchemy import Select
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.orm import Session

    # Imported for typing only: at runtime the ORM module is imported inside the
    # methods, because backend.db.orm.knowledge imports from rag.embeddings and a
    # module-level import here would close that cycle.
    from backend.db.orm.knowledge import KnowledgeChunk as KnowledgeChunkOrm

_logger = get_logger(__name__)

# Trust tiers in descending authority; used for the "minimum trust" filter.
_TRUST_ORDER: tuple[SourceTrustTier, ...] = (
    SourceTrustTier.AUTHORITATIVE,
    SourceTrustTier.VENDOR,
    SourceTrustTier.COMMUNITY,
    SourceTrustTier.INTERNAL,
)


def trust_rank(tier: SourceTrustTier) -> int:
    """Lower is more authoritative."""
    return _TRUST_ORDER.index(tier)


class EmbeddedChunk(KnowledgeChunkRecord):
    """A chunk paired with the embedding that will be indexed for it."""

    embedding: list[float]


class VectorStore(Protocol):
    """Storage and search over the knowledge corpus."""

    def add_chunks(self, chunks: Sequence[EmbeddedChunk], *, index_version: str) -> int: ...
    def activate_version(self, source_id: str, index_version: str) -> int: ...
    def active_version(self, source_id: str) -> str | None: ...
    def dense_search(
        self, embedding: Sequence[float], *, filters: RetrievalFilters, limit: int
    ) -> list[tuple[KnowledgeChunkRecord, float]]: ...
    def keyword_search(
        self, query: str, *, filters: RetrievalFilters, limit: int
    ) -> list[tuple[KnowledgeChunkRecord, float]]: ...
    def get_chunk(self, chunk_id: str) -> KnowledgeChunkRecord | None: ...


def matches_filters(record: KnowledgeChunkRecord, filters: RetrievalFilters) -> bool:
    """Whether a chunk satisfies every metadata filter."""
    metadata = record.metadata
    if filters.source_kinds and metadata.source_kind not in filters.source_kinds:
        return False
    if filters.cve_ids and (metadata.cve_id or "") not in filters.cve_ids:
        return False
    if filters.technique_ids and (metadata.technique_id or "") not in filters.technique_ids:
        return False
    if filters.products and not set(filters.products) & set(metadata.products):
        return False
    if filters.published_after:
        published = metadata.published_at
        if published is None or published < filters.published_after:
            return False
    return not (
        filters.minimum_trust
        and trust_rank(metadata.trust_tier) > trust_rank(filters.minimum_trust)
    )


def keyword_overlap_score(query: str, record: KnowledgeChunkRecord) -> float:
    """Lexical score: query-token coverage, boosted by exact identifier hits.

    Coverage (rather than raw frequency) keeps long chunks from dominating, and
    the identifier boost is what makes an exact "CVE-2021-44228" query land on
    the record for that CVE rather than on prose that merely mentions it.
    """
    query_tokens = set(tokenize(query))
    if not query_tokens:
        return 0.0

    haystack = f"{record.title or ''} {record.content}"
    document_tokens = set(tokenize(haystack))
    overlap = query_tokens & document_tokens
    score = len(overlap) / len(query_tokens)

    metadata = record.metadata
    identifiers = {
        value.lower()
        for value in (metadata.cve_id, metadata.technique_id, metadata.cwe_id)
        if value
    } | {product.lower() for product in metadata.products}
    if identifiers & query_tokens:
        score += 1.0
    return score


class InMemoryVectorStore:
    """In-process knowledge index for tests and local development."""

    def __init__(self) -> None:
        self._chunks: list[EmbeddedChunk] = []
        self._active: dict[str, str] = {}

    def add_chunks(self, chunks: Sequence[EmbeddedChunk], *, index_version: str) -> int:
        for chunk in chunks:
            self._chunks.append(chunk.model_copy(update={"index_version": index_version}))
        return len(chunks)

    def activate_version(self, source_id: str, index_version: str) -> int:
        previous = self._active.get(source_id)
        self._active[source_id] = index_version
        if previous is None or previous == index_version:
            return 0
        # Retire superseded chunks by dropping them from the searchable set while
        # leaving them addressable by id.
        retired = [
            chunk
            for chunk in self._chunks
            if chunk.metadata.source_id == source_id and chunk.index_version == previous
        ]
        return len(retired)

    def active_version(self, source_id: str) -> str | None:
        return self._active.get(source_id)

    def _searchable(self) -> list[EmbeddedChunk]:
        return [
            chunk
            for chunk in self._chunks
            if self._active.get(chunk.metadata.source_id) == chunk.index_version
        ]

    def dense_search(
        self, embedding: Sequence[float], *, filters: RetrievalFilters, limit: int
    ) -> list[tuple[KnowledgeChunkRecord, float]]:
        scored = [
            (chunk, cosine_similarity(embedding, chunk.embedding))
            for chunk in self._searchable()
            if matches_filters(chunk, filters)
        ]
        scored.sort(key=lambda item: (-item[1], item[0].chunk_id))
        return [(chunk, score) for chunk, score in scored[:limit] if score > 0.0]

    def keyword_search(
        self, query: str, *, filters: RetrievalFilters, limit: int
    ) -> list[tuple[KnowledgeChunkRecord, float]]:
        scored = [
            (chunk, keyword_overlap_score(query, chunk))
            for chunk in self._searchable()
            if matches_filters(chunk, filters)
        ]
        scored.sort(key=lambda item: (-item[1], item[0].chunk_id))
        return [(chunk, score) for chunk, score in scored[:limit] if score > 0.0]

    def get_chunk(self, chunk_id: str) -> KnowledgeChunkRecord | None:
        for chunk in self._chunks:
            if chunk.chunk_id == chunk_id:
                return chunk
        return None


class PgVectorStore:
    """PostgreSQL + pgvector knowledge index."""

    def __init__(self, session_scope: Callable[[], AbstractContextManager[Session]]) -> None:
        self._session_scope = session_scope

    @staticmethod
    def _to_record(row: KnowledgeChunkOrm) -> KnowledgeChunkRecord:
        return KnowledgeChunkRecord(
            chunk_id=row.chunk_id,
            document_id=row.document_id,
            title=row.title,
            content=row.content,
            ordinal=row.ordinal,
            parent_chunk_id=row.parent_chunk_id,
            index_version=row.index_version,
            metadata=ChunkMetadata(
                source_kind=row.source_kind,
                source_id=row.source_id,
                source_name=row.source_name,
                trust_tier=row.trust_tier,
                source_version=row.source_version,
                published_at=row.published_at,
                updated_at=row.source_updated_at,
                cve_id=row.cve_id,
                cwe_id=row.cwe_id,
                technique_id=row.technique_id,
                products=list(row.products or []),
                url=row.url,
                extra=dict(row.extra or {}),
            ),
        )

    def add_chunks(self, chunks: Sequence[EmbeddedChunk], *, index_version: str) -> int:
        from backend.db.orm.knowledge import KnowledgeChunk

        with self._session_scope() as session:
            for chunk in chunks:
                metadata = chunk.metadata
                session.add(
                    KnowledgeChunk(
                        chunk_id=chunk.chunk_id,
                        document_id=chunk.document_id,
                        title=chunk.title,
                        content=chunk.content,
                        embedding=chunk.embedding,
                        source_kind=metadata.source_kind,
                        source_id=metadata.source_id,
                        source_name=metadata.source_name,
                        trust_tier=metadata.trust_tier,
                        source_version=metadata.source_version,
                        published_at=metadata.published_at,
                        source_updated_at=metadata.updated_at,
                        cve_id=metadata.cve_id,
                        cwe_id=metadata.cwe_id,
                        technique_id=metadata.technique_id,
                        products=list(metadata.products),
                        url=metadata.url,
                        extra=dict(metadata.extra),
                        ordinal=chunk.ordinal,
                        parent_chunk_id=chunk.parent_chunk_id,
                        index_version=index_version,
                    )
                )
            session.flush()
        return len(chunks)

    def activate_version(self, source_id: str, index_version: str) -> int:
        """Flip the live version for a source and retire the previous one."""
        from sqlalchemy import select, update

        from backend.db.orm.knowledge import KnowledgeChunk, KnowledgeIndexVersion

        now = datetime.now(UTC)
        with self._session_scope() as session:
            previous = list(
                session.execute(
                    select(KnowledgeIndexVersion).where(
                        KnowledgeIndexVersion.source_id == source_id,
                        KnowledgeIndexVersion.status == IndexStatus.ACTIVE,
                        KnowledgeIndexVersion.version != index_version,
                    )
                )
                .scalars()
                .all()
            )

            retired = 0
            for record in previous:
                record.status = IndexStatus.RETIRED
                record.retired_at = now
                result = session.execute(
                    update(KnowledgeChunk)
                    .where(
                        KnowledgeChunk.source_id == source_id,
                        KnowledgeChunk.index_version == record.version,
                        KnowledgeChunk.retired_at.is_(None),
                    )
                    .values(retired_at=now)
                )
                retired += cast("CursorResult[Any]", result).rowcount

            current = session.execute(
                select(KnowledgeIndexVersion).where(
                    KnowledgeIndexVersion.source_id == source_id,
                    KnowledgeIndexVersion.version == index_version,
                )
            ).scalar_one_or_none()
            if current is not None:
                current.status = IndexStatus.ACTIVE
                current.activated_at = now
            session.flush()
        return retired

    def active_version(self, source_id: str) -> str | None:
        from sqlalchemy import select

        from backend.db.orm.knowledge import KnowledgeIndexVersion

        with self._session_scope() as session:
            return session.execute(
                select(KnowledgeIndexVersion.version).where(
                    KnowledgeIndexVersion.source_id == source_id,
                    KnowledgeIndexVersion.status == IndexStatus.ACTIVE,
                )
            ).scalar_one_or_none()

    def record_version(
        self,
        *,
        source_id: str,
        version: str,
        embedding_model: str,
        embedding_dimensions: int,
        document_count: int,
        chunk_count: int,
    ) -> None:
        """Register a newly built index version (status: building)."""
        from backend.db.orm.knowledge import KnowledgeIndexVersion

        with self._session_scope() as session:
            session.add(
                KnowledgeIndexVersion(
                    source_id=source_id,
                    version=version,
                    embedding_model=embedding_model,
                    embedding_dimensions=embedding_dimensions,
                    status=IndexStatus.BUILDING,
                    document_count=document_count,
                    chunk_count=chunk_count,
                )
            )
            session.flush()

    def _base_query(self, filters: RetrievalFilters) -> Select[tuple[KnowledgeChunkOrm]]:
        from sqlalchemy import select

        from backend.db.orm.knowledge import KnowledgeChunk

        stmt = select(KnowledgeChunk).where(KnowledgeChunk.retired_at.is_(None))
        if filters.source_kinds:
            stmt = stmt.where(KnowledgeChunk.source_kind.in_(filters.source_kinds))
        if filters.cve_ids:
            stmt = stmt.where(KnowledgeChunk.cve_id.in_(filters.cve_ids))
        if filters.technique_ids:
            stmt = stmt.where(KnowledgeChunk.technique_id.in_(filters.technique_ids))
        if filters.published_after:
            stmt = stmt.where(KnowledgeChunk.published_at >= filters.published_after)
        if filters.minimum_trust:
            allowed = [
                tier
                for tier in _TRUST_ORDER
                if trust_rank(tier) <= trust_rank(filters.minimum_trust)
            ]
            stmt = stmt.where(KnowledgeChunk.trust_tier.in_(allowed))
        return stmt

    def dense_search(
        self, embedding: Sequence[float], *, filters: RetrievalFilters, limit: int
    ) -> list[tuple[KnowledgeChunkRecord, float]]:
        """Nearest neighbours by cosine distance, converted to a similarity score."""
        from backend.db.orm.knowledge import KnowledgeChunk

        distance = KnowledgeChunk.embedding.cosine_distance(list(embedding))
        stmt = (
            self._base_query(filters)
            .add_columns(distance.label("distance"))
            .order_by(distance)
            .limit(limit)
        )

        with self._session_scope() as session:
            rows = list(session.execute(stmt))
            results = [
                (self._to_record(row[0]), 1.0 - float(row[1]))
                for row in rows
                if matches_filters(self._to_record(row[0]), filters)
            ]
        return [(record, score) for record, score in results if score > 0.0]

    def keyword_search(
        self, query: str, *, filters: RetrievalFilters, limit: int
    ) -> list[tuple[KnowledgeChunkRecord, float]]:
        """Lexical search over identifiers and full text.

        Identifier equality is checked in SQL (that is the precise path), while
        general term overlap is scored in Python against a bounded candidate set,
        keeping the scoring identical to the in-process store.
        """
        from sqlalchemy import or_

        from backend.db.orm.knowledge import KnowledgeChunk

        tokens = tokenize(query)
        stmt = self._base_query(filters)
        if tokens:
            upper = [token.upper() for token in tokens]
            conditions = [
                KnowledgeChunk.cve_id.in_(upper),
                KnowledgeChunk.technique_id.in_(upper),
                KnowledgeChunk.cwe_id.in_(upper),
            ]
            conditions.extend(
                KnowledgeChunk.content.ilike(f"%{token}%") for token in tokens if len(token) > 2
            )
            conditions.append(KnowledgeChunk.title.ilike(f"%{query}%"))
            stmt = stmt.where(or_(*conditions))
        stmt = stmt.limit(limit)

        with self._session_scope() as session:
            rows = list(session.execute(stmt).scalars().all())

        scored = [
            (record, keyword_overlap_score(query, record))
            for record in (self._to_record(row) for row in rows)
        ]
        scored.sort(key=lambda item: (-item[1], item[0].chunk_id))
        return [(record, score) for record, score in scored[:limit] if score > 0.0]

    def get_chunk(self, chunk_id: str) -> KnowledgeChunkRecord | None:
        """Resolve a chunk by id, including retired ones (citations must resolve)."""
        from sqlalchemy import select

        from backend.db.orm.knowledge import KnowledgeChunk

        with self._session_scope() as session:
            row = (
                session.execute(
                    select(KnowledgeChunk)
                    .where(KnowledgeChunk.chunk_id == chunk_id)
                    .order_by(KnowledgeChunk.created_at.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
            return self._to_record(row) if row is not None else None

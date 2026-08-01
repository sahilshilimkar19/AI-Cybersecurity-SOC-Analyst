"""RAG layer — the Retrieval-Augmented Generation pipeline.

Grounds agents in authoritative security knowledge and is the mechanism for
citations (invariant #4). The pipeline runs:

    fetch → clean → dedupe → chunk → embed → index      (ingestion)
    query → dense + keyword + filters → fuse → rank → cite   (retrieval)

Three properties are load-bearing:

* **Allow-listed sources only.** Unknown provenance never enters the corpus
  agents reason from — a security control, not a curation preference.
* **Versioned indexes, atomic swaps.** A refresh builds a new version and flips
  it in one step; superseded chunks are retired, not deleted, so a retrieval that
  recorded a version can still be replayed against exactly what it saw.
* **Citations resolve.** Every retrieved chunk yields a citation pointing back at
  the passage that supports the claim.

Agents never call this module directly; they reach it through the read-only
knowledge memory tier.

See docs/ENGINEERING_DESIGN_SPEC.md §8 and docs/adr/0006-rag-pipeline.md.
"""

from __future__ import annotations

from rag.cache import RetrievalCache, cache_key
from rag.chunking import Chunker, clean_text, split_sections
from rag.citations import CitationResolver, bind_citation, bind_citations
from rag.embeddings import (
    EMBEDDING_DIMENSIONS,
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    build_embedding_provider,
    cosine_similarity,
    tokenize,
)
from rag.errors import (
    EmbeddingDimensionError,
    IndexUnavailableError,
    IngestionError,
    RagConfigurationError,
    RagError,
    UntrustedSourceError,
)
from rag.index import (
    EmbeddedChunk,
    InMemoryVectorStore,
    PgVectorStore,
    VectorStore,
    matches_filters,
)
from rag.ingestion import IngestionPipeline, build_index_version
from rag.knowledge_memory import RagKnowledgeMemory
from rag.ranking import freshness_weight, fuse, rank, take_within_budget, trust_weight
from rag.retriever import HybridRetriever, expand_query
from rag.service import RagService, build_rag_service
from rag.sources import (
    DEFAULT_SOURCES,
    DocumentFetcher,
    FilesystemFetcher,
    InMemoryFetcher,
    SourceDefinition,
    SourceRegistry,
)

__all__ = [
    "DEFAULT_SOURCES",
    "EMBEDDING_DIMENSIONS",
    "Chunker",
    "CitationResolver",
    "DeterministicEmbeddingProvider",
    "DocumentFetcher",
    "EmbeddedChunk",
    "EmbeddingDimensionError",
    "EmbeddingProvider",
    "FilesystemFetcher",
    "HybridRetriever",
    "InMemoryFetcher",
    "InMemoryVectorStore",
    "IndexUnavailableError",
    "IngestionError",
    "IngestionPipeline",
    "PgVectorStore",
    "RagConfigurationError",
    "RagError",
    "RagKnowledgeMemory",
    "RagService",
    "RetrievalCache",
    "SourceDefinition",
    "SourceRegistry",
    "UntrustedSourceError",
    "VectorStore",
    "bind_citation",
    "bind_citations",
    "build_embedding_provider",
    "build_index_version",
    "build_rag_service",
    "cache_key",
    "clean_text",
    "cosine_similarity",
    "expand_query",
    "freshness_weight",
    "fuse",
    "matches_filters",
    "rank",
    "split_sections",
    "take_within_budget",
    "tokenize",
    "trust_weight",
]

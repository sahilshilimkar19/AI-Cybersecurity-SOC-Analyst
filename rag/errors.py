"""Errors raised by the RAG pipeline."""

from __future__ import annotations


class RagError(Exception):
    """Base error for the RAG pipeline."""


class RagConfigurationError(RagError):
    """A component was configured with an unsupported backend or setting."""


class UntrustedSourceError(RagError):
    """A document came from a source that is not on the allow-list.

    Only allow-listed sources may ground an answer; unknown provenance is
    excluded rather than ranked low (EDS §8 source trust).
    """


class EmbeddingDimensionError(RagError):
    """An embedding did not match the dimensions pinned for the index."""


class IngestionError(RagError):
    """A source failed to ingest. Failures are isolated per source."""


class IndexUnavailableError(RagError):
    """The knowledge index could not be reached for a retrieval."""

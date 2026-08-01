"""The embedding provider port (EDS §8 embedding strategy).

Embeddings are produced behind a protocol so the pipeline never depends on a
specific vendor. One model is **pinned per index version**: changing the model or
its dimensions means re-embedding the corpus under a *new* index version, never
editing vectors in place, because a corpus embedded by two different models is
not comparable and silently degrades retrieval.

The default provider is deterministic and model-free — a hashing embedder that
maps tokens into a fixed-dimension space. It is not semantic, and it is not meant
to be: it makes the whole pipeline (ingestion, indexing, hybrid retrieval,
ranking, citations) testable and reproducible offline. A model-backed provider
implements this same protocol when the AI layer lands, and its arrival is exactly
an index-version change.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import TYPE_CHECKING, Protocol

from rag.errors import EmbeddingDimensionError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from config.settings import Settings

# Fixed for the shipped provider. The vector column is declared with this width,
# so a provider with different dimensions requires a migration alongside its new
# index version.
EMBEDDING_DIMENSIONS = 384

_TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*")


def tokenize(text: str) -> list[str]:
    """Split text into lowercase tokens.

    Identifier characters (``.``, ``_``, ``-``) are kept inside tokens so
    "CVE-2021-44228" and "log4j-core" survive as single units instead of being
    shredded into meaningless fragments.
    """
    return _TOKEN_PATTERN.findall(text.lower())


class EmbeddingProvider(Protocol):
    """Turns text into vectors for the knowledge index."""

    @property
    def model(self) -> str: ...
    @property
    def dimensions(self) -> int: ...
    def embed(self, text: str) -> list[float]: ...
    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]: ...


class DeterministicEmbeddingProvider:
    """Hashing embedder: same text always yields the same vector.

    Tokens are hashed into dimensions with a sub-linear frequency weight and the
    result is L2-normalized, so cosine similarity behaves sensibly and shared
    vocabulary drives similarity.
    """

    def __init__(
        self, *, model: str = "deterministic-hash-v1", dimensions: int = EMBEDDING_DIMENSIONS
    ) -> None:
        if dimensions <= 0:
            raise EmbeddingDimensionError("embedding dimensions must be positive")
        self._model = model
        self._dimensions = dimensions

    @property
    def model(self) -> str:
        return self._model

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self._dimensions
        counts: dict[str, int] = {}
        for token in tokenize(text):
            counts[token] = counts.get(token, 0) + 1

        for token, count in counts.items():
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self._dimensions
            # Sign spreads tokens across the space so unrelated terms do not all
            # push in the same direction.
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[bucket] += sign * (1.0 + math.log(count))

        return _normalize(vector)

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        return [self.embed(text) for text in texts]


def _normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return vector
    return [value / norm for value in vector]


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    """Cosine similarity between two vectors (0.0 when either is degenerate)."""
    if len(left) != len(right):
        raise EmbeddingDimensionError(f"vector dimensions differ: {len(left)} != {len(right)}")
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def build_embedding_provider(settings: Settings) -> EmbeddingProvider:
    """Build the configured embedding provider (fail-fast on unknown)."""
    from rag.errors import RagConfigurationError

    provider = settings.embedding_provider
    if provider == "deterministic":
        return DeterministicEmbeddingProvider(model=settings.embedding_model)
    raise RagConfigurationError(f"unsupported embedding provider: {provider!r}")

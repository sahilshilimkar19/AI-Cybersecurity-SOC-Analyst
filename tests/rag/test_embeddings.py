"""Tests for the embedding provider port."""

import pytest

from config.settings import Settings
from rag.embeddings import (
    EMBEDDING_DIMENSIONS,
    DeterministicEmbeddingProvider,
    build_embedding_provider,
    cosine_similarity,
    tokenize,
)
from rag.errors import EmbeddingDimensionError, RagConfigurationError


def test_tokenize_keeps_identifiers_intact() -> None:
    # A CVE id must survive as one token, or exact retrieval falls apart.
    assert "cve-2021-44228" in tokenize("Details for CVE-2021-44228 here")
    assert "log4j-core" in tokenize("package log4j-core is affected")


def test_tokenize_lowercases_and_drops_punctuation() -> None:
    assert tokenize("Hello, World!") == ["hello", "world"]


def test_embedding_is_deterministic() -> None:
    provider = DeterministicEmbeddingProvider()
    assert provider.embed("log4shell") == provider.embed("log4shell")


def test_embedding_has_the_pinned_dimensions() -> None:
    provider = DeterministicEmbeddingProvider()
    assert provider.dimensions == EMBEDDING_DIMENSIONS
    assert len(provider.embed("anything")) == EMBEDDING_DIMENSIONS


def test_embedding_is_normalized() -> None:
    vector = DeterministicEmbeddingProvider().embed("apache log4j remote code execution")
    magnitude = sum(value * value for value in vector) ** 0.5
    assert magnitude == pytest.approx(1.0)


def test_empty_text_embeds_to_a_zero_vector() -> None:
    assert set(DeterministicEmbeddingProvider().embed("")) == {0.0}


def test_shared_vocabulary_scores_higher_than_unrelated_text() -> None:
    provider = DeterministicEmbeddingProvider()
    query = provider.embed("log4j remote code execution")
    related = provider.embed("apache log4j allows remote code execution")
    unrelated = provider.embed("ransomware containment backup restoration")

    assert cosine_similarity(query, related) > cosine_similarity(query, unrelated)


def test_batch_matches_single_embedding() -> None:
    provider = DeterministicEmbeddingProvider()
    texts = ["alpha", "beta"]
    assert provider.embed_batch(texts) == [provider.embed(text) for text in texts]


def test_cosine_similarity_of_zero_vector_is_zero() -> None:
    assert cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0


def test_cosine_similarity_rejects_mismatched_dimensions() -> None:
    with pytest.raises(EmbeddingDimensionError):
        cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0])


def test_non_positive_dimensions_are_rejected() -> None:
    with pytest.raises(EmbeddingDimensionError):
        DeterministicEmbeddingProvider(dimensions=0)


def test_factory_builds_the_configured_provider() -> None:
    provider = build_embedding_provider(Settings(embedding_model="pinned-v2"))
    assert provider.model == "pinned-v2"


def test_factory_rejects_an_unknown_provider() -> None:
    from types import SimpleNamespace

    with pytest.raises(RagConfigurationError):
        build_embedding_provider(SimpleNamespace(embedding_provider="mystery"))  # type: ignore[arg-type]

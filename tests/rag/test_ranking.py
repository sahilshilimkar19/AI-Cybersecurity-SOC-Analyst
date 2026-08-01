"""Tests for fusion, freshness/trust weighting, and budgeted selection."""

from datetime import UTC, datetime, timedelta

import pytest

from memory.summarization import estimate_tokens
from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import ChunkMetadata, KnowledgeChunkRecord, RetrievedChunk
from rag.ranking import (
    freshness_weight,
    fuse,
    rank,
    take_within_budget,
    trust_weight,
)

NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _record(
    chunk_id: str,
    *,
    published: datetime | None = None,
    trust: SourceTrustTier = SourceTrustTier.AUTHORITATIVE,
    content: str = "content",
) -> KnowledgeChunkRecord:
    return KnowledgeChunkRecord(
        chunk_id=chunk_id,
        document_id=chunk_id,
        content=content,
        metadata=ChunkMetadata(
            source_kind=KnowledgeSourceKind.NVD,
            source_id="nvd",
            source_name="NVD",
            trust_tier=trust,
            published_at=published,
        ),
    )


def test_undated_sources_are_not_penalized() -> None:
    assert freshness_weight(None, half_life_days=180) == 1.0


def test_freshness_halves_at_the_half_life() -> None:
    published = NOW - timedelta(days=180)
    assert freshness_weight(published, half_life_days=180, now=NOW) == pytest.approx(0.5)


def test_newer_sources_weigh_more_than_older_ones() -> None:
    recent = freshness_weight(NOW - timedelta(days=10), half_life_days=180, now=NOW)
    old = freshness_weight(NOW - timedelta(days=900), half_life_days=180, now=NOW)
    assert recent > old


def test_future_dates_are_treated_as_current() -> None:
    assert freshness_weight(NOW + timedelta(days=5), half_life_days=180, now=NOW) == 1.0


def test_naive_timestamps_are_treated_as_utc() -> None:
    naive = datetime(2026, 7, 1)
    assert 0.0 < freshness_weight(naive, half_life_days=180, now=NOW) <= 1.0


def test_trust_weights_prefer_authoritative_sources() -> None:
    assert trust_weight(SourceTrustTier.AUTHORITATIVE) > trust_weight(SourceTrustTier.VENDOR)
    assert trust_weight(SourceTrustTier.VENDOR) > trust_weight(SourceTrustTier.COMMUNITY)


def test_fuse_deduplicates_chunks_found_by_both_paths() -> None:
    record = _record("c1")
    fused = fuse([(record, 0.8)], [(record, 0.6)])

    assert len(fused) == 1
    assert fused[0].dense_score == 0.8
    assert fused[0].keyword_score == 0.6
    assert fused[0].matched_by == ["dense", "keyword"]


def test_fuse_keeps_chunks_found_by_only_one_path() -> None:
    fused = fuse([(_record("c1"), 0.5)], [(_record("c2"), 0.5)])
    assert {item.chunk.chunk_id for item in fused} == {"c1", "c2"}


def test_ranking_prefers_the_fresher_of_two_equal_matches() -> None:
    fresh = RetrievedChunk(
        chunk=_record("fresh", published=NOW - timedelta(days=5)), dense_score=1.0
    )
    stale = RetrievedChunk(
        chunk=_record("stale", published=NOW - timedelta(days=1200)), dense_score=1.0
    )

    ranked = rank([stale, fresh], half_life_days=180, now=NOW)
    assert [item.chunk.chunk_id for item in ranked] == ["fresh", "stale"]


def test_ranking_prefers_the_more_trusted_of_two_equal_matches() -> None:
    authoritative = RetrievedChunk(
        chunk=_record("auth", trust=SourceTrustTier.AUTHORITATIVE), dense_score=1.0
    )
    community = RetrievedChunk(
        chunk=_record("comm", trust=SourceTrustTier.COMMUNITY), dense_score=1.0
    )

    ranked = rank([community, authoritative], half_life_days=180, now=NOW)
    assert [item.chunk.chunk_id for item in ranked] == ["auth", "comm"]


def test_old_but_exact_match_outranks_a_recent_weak_match() -> None:
    """Freshness must not annihilate scores.

    Unbounded decay made a five-year-old CVE record unrankable regardless of how
    exactly it matched, letting a recent but barely-relevant document win. Older
    canonical records (ATT&CK techniques, foundational CVEs) have to stay reachable.
    """
    old_exact = RetrievedChunk(
        chunk=_record("old-exact", published=NOW - timedelta(days=2200)),
        dense_score=1.0,
        keyword_score=1.0,
    )
    recent_weak = RetrievedChunk(
        chunk=_record("recent-weak", published=NOW - timedelta(days=5)),
        dense_score=0.1,
        keyword_score=0.1,
    )

    ranked = rank([recent_weak, old_exact], half_life_days=180, now=NOW)
    assert [item.chunk.chunk_id for item in ranked] == ["old-exact", "recent-weak"]


def test_freshness_can_at_most_halve_a_score() -> None:
    ancient = RetrievedChunk(
        chunk=_record("ancient", published=NOW - timedelta(days=36_500)), dense_score=1.0
    )
    ranked = rank([ancient], half_life_days=180, now=NOW)
    # Raw decay is ~0, but the applied modifier is floored.
    assert ranked[0].score == pytest.approx(0.45 * 0.5, rel=1e-6)


def test_ranking_records_the_applied_weights() -> None:
    ranked = rank(
        [RetrievedChunk(chunk=_record("c1", published=NOW - timedelta(days=180)), dense_score=1.0)],
        half_life_days=180,
        now=NOW,
    )
    assert ranked[0].freshness_weight == pytest.approx(0.5)
    assert ranked[0].trust_weight == 1.0
    assert ranked[0].score > 0


def test_ranking_is_deterministic_for_tied_scores() -> None:
    candidates = [
        RetrievedChunk(chunk=_record("b"), dense_score=1.0),
        RetrievedChunk(chunk=_record("a"), dense_score=1.0),
    ]
    assert [item.chunk.chunk_id for item in rank(candidates, half_life_days=180, now=NOW)] == [
        "a",
        "b",
    ]


def test_ranking_an_empty_candidate_set_is_empty() -> None:
    assert rank([], half_life_days=180, now=NOW) == []


def test_take_within_budget_respects_top_k() -> None:
    candidates = [RetrievedChunk(chunk=_record(f"c{i}")) for i in range(10)]
    assert (
        len(take_within_budget(candidates, top_k=3, token_budget=10_000, estimate=estimate_tokens))
        == 3
    )


def test_take_within_budget_stops_at_the_token_budget() -> None:
    candidates = [RetrievedChunk(chunk=_record(f"c{i}", content="x" * 400)) for i in range(5)]
    selected = take_within_budget(candidates, top_k=5, token_budget=150, estimate=estimate_tokens)
    assert 0 < len(selected) < 5


def test_take_within_budget_always_returns_at_least_one_chunk() -> None:
    candidates = [RetrievedChunk(chunk=_record("big", content="x" * 10_000))]
    assert (
        len(take_within_budget(candidates, top_k=5, token_budget=10, estimate=estimate_tokens)) == 1
    )

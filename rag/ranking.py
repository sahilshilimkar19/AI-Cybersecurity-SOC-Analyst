"""Fusion and re-ranking of hybrid retrieval results (EDS §8 ranking).

The dense and keyword paths are fused, deduplicated, then weighted by **freshness**
and **source trust**. Both weights matter for safety rather than taste: acting on
an out-of-date remediation can cause harm, and a claim resting on a weak source
should not outrank the authoritative record.

Freshness decays with a configurable half-life; documents without a publication
date are treated as neutral rather than penalized, because "undated" is not the
same as "old".
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from models.enums import SourceTrustTier
from models.knowledge import RetrievedChunk

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from models.knowledge import KnowledgeChunkRecord

# Relative influence of each retrieval path. Keyword is weighted slightly higher
# because security queries are frequently exact (a CVE id, a product name), and a
# lexical hit on an identifier is stronger evidence than semantic nearness.
DENSE_WEIGHT = 0.45
KEYWORD_WEIGHT = 0.55

# Freshness is applied as a *bounded* modifier: at worst it halves a score.
#
# Raw exponential decay is unbounded, and over a multi-year corpus that is fatal —
# a five-year-old CVE record decays to ~0.001 and becomes unrankable no matter how
# exactly it matches. But CVE-2021-44228 is still the authority on Log4Shell, and
# ATT&CK techniques are older still. The requirement is that newer advisories are
# *preferred*, not that older canonical records become invisible, so decay is
# compressed into [FRESHNESS_FLOOR, 1.0].
FRESHNESS_FLOOR = 0.5

# Multiplier per trust tier, in descending authority.
_TRUST_WEIGHTS: dict[SourceTrustTier, float] = {
    SourceTrustTier.AUTHORITATIVE: 1.0,
    SourceTrustTier.VENDOR: 0.9,
    SourceTrustTier.COMMUNITY: 0.75,
    SourceTrustTier.INTERNAL: 0.85,
}


def trust_weight(tier: SourceTrustTier) -> float:
    """Ranking multiplier for a source trust tier."""
    return _TRUST_WEIGHTS.get(tier, 0.5)


def freshness_weight(
    published_at: datetime | None, *, half_life_days: float, now: datetime | None = None
) -> float:
    """Exponential decay by age; ``1.0`` for undated or future-dated sources."""
    if published_at is None:
        return 1.0
    reference = now or datetime.now(UTC)
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=UTC)
    age_days = (reference - published_at).total_seconds() / 86_400
    if age_days <= 0:
        return 1.0
    return math.pow(0.5, age_days / half_life_days)


def fuse(
    dense: Sequence[tuple[KnowledgeChunkRecord, float]],
    keyword: Sequence[tuple[KnowledgeChunkRecord, float]],
) -> list[RetrievedChunk]:
    """Merge both retrieval paths, deduplicating on chunk id."""
    merged: dict[str, RetrievedChunk] = {}

    for record, score in dense:
        merged[record.chunk_id] = RetrievedChunk(
            chunk=record, dense_score=score, matched_by=["dense"]
        )

    for record, score in keyword:
        existing = merged.get(record.chunk_id)
        if existing is None:
            merged[record.chunk_id] = RetrievedChunk(
                chunk=record, keyword_score=score, matched_by=["keyword"]
            )
        else:
            merged[record.chunk_id] = existing.model_copy(
                update={
                    "keyword_score": score,
                    "matched_by": [*existing.matched_by, "keyword"],
                }
            )

    return list(merged.values())


def rank(
    candidates: Sequence[RetrievedChunk],
    *,
    half_life_days: float,
    now: datetime | None = None,
) -> list[RetrievedChunk]:
    """Score and order candidates by relevance, freshness, and trust."""
    normalized_dense = _normalize([item.dense_score for item in candidates])
    normalized_keyword = _normalize([item.keyword_score for item in candidates])

    ranked: list[RetrievedChunk] = []
    for index, item in enumerate(candidates):
        metadata = item.chunk.metadata
        fresh = freshness_weight(metadata.published_at, half_life_days=half_life_days, now=now)
        trust = trust_weight(metadata.trust_tier)
        relevance = (
            DENSE_WEIGHT * normalized_dense[index] + KEYWORD_WEIGHT * normalized_keyword[index]
        )
        # The raw decay is reported for transparency; the bounded form is applied.
        applied_freshness = FRESHNESS_FLOOR + (1.0 - FRESHNESS_FLOOR) * fresh
        ranked.append(
            item.model_copy(
                update={
                    "freshness_weight": fresh,
                    "trust_weight": trust,
                    "score": relevance * applied_freshness * trust,
                }
            )
        )

    # Chunk id breaks ties so ordering is deterministic and reproducible.
    ranked.sort(key=lambda item: (-item.score, item.chunk.chunk_id))
    return ranked


def take_within_budget(
    ranked: Sequence[RetrievedChunk],
    *,
    top_k: int,
    token_budget: int,
    estimate: Callable[[str], int],
) -> list[RetrievedChunk]:
    """Take the best chunks that fit both the top-k cap and the token budget.

    The budget is a hard stop: context that overflows it would be truncated
    somewhere less careful, and a silently truncated citation is worse than one
    chunk fewer.
    """
    selected: list[RetrievedChunk] = []
    used = 0
    for item in ranked[:top_k]:
        cost = estimate(item.chunk.content)
        if selected and used + cost > token_budget:
            break
        selected.append(item)
        used += cost
    return selected


def _normalize(scores: Sequence[float]) -> list[float]:
    """Scale scores to 0..1 so the two paths are comparable before fusion."""
    if not scores:
        return []
    highest = max(scores)
    if highest <= 0:
        return [0.0 for _ in scores]
    return [score / highest for score in scores]

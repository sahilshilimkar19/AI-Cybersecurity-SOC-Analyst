"""Retrieval cache and degradation fallback (EDS §8 caching).

Entries are keyed by ``query + filters + index version``, so a corpus refresh
naturally invalidates results rather than serving answers from an index that no
longer exists.

The cache doubles as the **degradation path**: if the index is unreachable, the
last good result for that query is served with ``stale=True`` set, letting an
investigation continue with knowledge that is explicitly marked as possibly
out-of-date instead of failing outright (invariant #6). Stale entries are served
past their TTL precisely because the alternative — no grounding at all — is worse,
but they always announce themselves.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from models.knowledge import RetrievalResult

if TYPE_CHECKING:
    from models.knowledge import RetrievalFilters


def cache_key(query: str, filters: RetrievalFilters, index_version: str | None) -> str:
    """Stable key over the query, its filters, and the corpus version."""
    digest = hashlib.sha256()
    digest.update(query.strip().lower().encode("utf-8"))
    digest.update(filters.model_dump_json(exclude_none=True).encode("utf-8"))
    digest.update((index_version or "").encode("utf-8"))
    return digest.hexdigest()


@dataclass
class _Entry:
    result: RetrievalResult
    expires_at: datetime


class RetrievalCache:
    """In-process TTL cache for retrieval results."""

    def __init__(self, *, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, _Entry] = {}

    @property
    def enabled(self) -> bool:
        """Whether caching is switched on (a zero TTL disables it)."""
        return self._ttl > 0

    def get(self, key: str, *, now: datetime | None = None) -> RetrievalResult | None:
        """Return a fresh cached result, or ``None`` if absent or expired."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if (now or datetime.now(UTC)) >= entry.expires_at:
            return None
        return entry.result.model_copy(update={"cached": True})

    def get_stale(self, key: str) -> RetrievalResult | None:
        """Return a cached result regardless of age, flagged as stale.

        Used only when the index is unreachable.
        """
        entry = self._entries.get(key)
        if entry is None:
            return None
        return entry.result.model_copy(update={"cached": True, "stale": True})

    def set(self, key: str, result: RetrievalResult, *, now: datetime | None = None) -> None:
        """Cache a result if caching is enabled."""
        if not self.enabled:
            return
        reference = now or datetime.now(UTC)
        self._entries[key] = _Entry(
            result=result.model_copy(update={"cached": False, "stale": False}),
            expires_at=reference + timedelta(seconds=self._ttl),
        )

    def clear(self) -> None:
        """Drop every cached result."""
        self._entries.clear()

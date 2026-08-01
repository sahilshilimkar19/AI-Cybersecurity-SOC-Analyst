"""Session memory — two-tier, investigation-scoped (EDS §7).

One investigation's evolving context, shared by the nodes working on it. It spans
a fast hot tier (Redis) and a durable tier (PostgreSQL):

* **Writes are write-through, durable first.** The durable tier is the source of
  truth, so it is never behind the cache: if the hot write fails afterwards the
  worst case is a cache miss, not a lost fact.
* **Reads try hot, then fall back to durable** and repopulate the cache. A cold
  or evicted cache therefore costs one extra read, never a wrong answer.
* **Rebuild** reloads the whole working set from durable storage, which is how an
  investigation survives a worker restart or a flushed Redis (invariant #6).

Writes append a new revision rather than overwriting, so what an earlier node saw
remains inspectable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from config.logging import get_logger
from models.memory import MemoryEntry, MemoryStats

if TYPE_CHECKING:
    from memory.durable import DurableMemoryStore
    from memory.hot import HotMemoryStore

_logger = get_logger(__name__)


class SessionMemory:
    """Investigation-scoped memory across the hot and durable tiers."""

    def __init__(self, *, hot: HotMemoryStore, durable: DurableMemoryStore) -> None:
        self._hot = hot
        self._durable = durable
        self._stats = MemoryStats()

    @property
    def stats(self) -> MemoryStats:
        """Hit/miss/recovery counters for this manager."""
        return self._stats.model_copy()

    def write(
        self, investigation_id: UUID, key: str, value: dict[str, Any], *, source: str
    ) -> MemoryEntry:
        """Append a revision durably, then refresh the hot tier (write-through)."""
        entry = self._durable.append(
            investigation_id=investigation_id, key=key, value=value, source=source
        )
        try:
            self._hot.set(investigation_id, entry)
        except Exception:  # pragma: no cover - depends on a live Redis failing
            # The durable write already succeeded; a cache failure must not fail
            # the investigation. The next read falls back and repopulates.
            _logger.warning(
                "hot_memory_write_failed",
                investigation_id=str(investigation_id),
                key=key,
                exc_info=True,
            )
        return entry

    def read(self, investigation_id: UUID, key: str) -> MemoryEntry | None:
        """Read a key: hot first, then durable (repopulating the cache)."""
        cached = self._hot.get(investigation_id, key)
        if cached is not None:
            self._stats.hits += 1
            return cached

        self._stats.misses += 1
        entry = self._durable.latest(investigation_id, key)
        if entry is not None:
            self._hot.set(investigation_id, entry)
        return entry

    def read_all(self, investigation_id: UUID) -> list[MemoryEntry]:
        """Return the whole working set, rebuilding the cache when it is cold."""
        cached = self._hot.get_all(investigation_id)
        if cached:
            self._stats.hits += 1
            return sorted(cached, key=lambda entry: entry.key)

        self._stats.misses += 1
        return self.rebuild(investigation_id)

    def rebuild(self, investigation_id: UUID) -> list[MemoryEntry]:
        """Reload the hot tier from durable storage (restart / cache-loss recovery)."""
        entries = self._durable.latest_all(investigation_id)
        for entry in entries:
            self._hot.set(investigation_id, entry)
        self._stats.recoveries += 1
        _logger.info(
            "session_memory_rebuilt",
            investigation_id=str(investigation_id),
            entries=len(entries),
        )
        return sorted(entries, key=lambda entry: entry.key)

    def history(self, investigation_id: UUID, key: str) -> list[MemoryEntry]:
        """Return every retained revision of a key (the provenance trail)."""
        return self._durable.history(investigation_id, key)

    def evict_hot(self, investigation_id: UUID) -> None:
        """Drop the hot copy. Durable memory is retained for audit and archival."""
        self._hot.clear(investigation_id)
        self._stats.evictions += 1

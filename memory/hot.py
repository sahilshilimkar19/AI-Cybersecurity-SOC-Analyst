"""The hot (fast) half of session memory (EDS §7).

A small interface with an in-process implementation for tests/local runs and a
Redis implementation for real deployments, mirroring the object-store and
session-store patterns (ADR 0002/0003).

The hot tier is a **cache, never the source of truth**: entries carry a TTL and
may vanish at any time. Every read path falls back to the durable tier, so losing
Redis costs latency, not data (invariant #6).
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from models.memory import MemoryEntry

if TYPE_CHECKING:
    from redis import Redis

    from config.settings import Settings


class HotBackend(StrEnum):
    """Supported hot-tier backends."""

    MEMORY = "memory"
    REDIS = "redis"


class HotMemoryStore(Protocol):
    """Per-investigation hot storage for session-memory entries."""

    def get(self, investigation_id: UUID, key: str) -> MemoryEntry | None: ...
    def set(self, investigation_id: UUID, entry: MemoryEntry) -> None: ...
    def get_all(self, investigation_id: UUID) -> list[MemoryEntry]: ...
    def clear(self, investigation_id: UUID) -> None: ...


class InMemoryHotStore:
    """In-process hot store for tests and single-process local development."""

    def __init__(self) -> None:
        self._data: dict[UUID, dict[str, MemoryEntry]] = {}

    def get(self, investigation_id: UUID, key: str) -> MemoryEntry | None:
        return self._data.get(investigation_id, {}).get(key)

    def set(self, investigation_id: UUID, entry: MemoryEntry) -> None:
        self._data.setdefault(investigation_id, {})[entry.key] = entry

    def get_all(self, investigation_id: UUID) -> list[MemoryEntry]:
        return list(self._data.get(investigation_id, {}).values())

    def clear(self, investigation_id: UUID) -> None:
        self._data.pop(investigation_id, None)


class RedisHotStore:
    """Redis-backed hot store.

    Each investigation is one hash (field per memory key) so the whole working
    set is fetched in a single round trip and expires as a unit.
    """

    def __init__(self, client: Redis, *, namespace: str, ttl_seconds: int) -> None:
        self._redis = client
        self._ns = namespace
        self._ttl = ttl_seconds

    def _key(self, investigation_id: UUID) -> str:
        return f"{self._ns}:session:{investigation_id}"

    def get(self, investigation_id: UUID, key: str) -> MemoryEntry | None:
        raw = self._redis.hget(self._key(investigation_id), key)
        return MemoryEntry.model_validate_json(raw) if raw else None

    def set(self, investigation_id: UUID, entry: MemoryEntry) -> None:
        redis_key = self._key(investigation_id)
        self._redis.hset(redis_key, entry.key, entry.model_dump_json())
        # Refresh the TTL on every write so an active investigation stays hot.
        self._redis.expire(redis_key, self._ttl)

    def get_all(self, investigation_id: UUID) -> list[MemoryEntry]:
        raw = self._redis.hgetall(self._key(investigation_id))
        return [MemoryEntry.model_validate_json(value) for value in raw.values()]

    def clear(self, investigation_id: UUID) -> None:
        self._redis.delete(self._key(investigation_id))


def build_hot_store(settings: Settings, *, client: Redis | None = None) -> HotMemoryStore:
    """Build the hot store for the configured backend (fail-fast on unknown)."""
    from memory.errors import MemoryConfigurationError

    backend = settings.memory_hot_backend
    if backend == HotBackend.MEMORY:
        return InMemoryHotStore()
    if backend == HotBackend.REDIS:
        if client is None:
            import redis

            client = redis.Redis.from_url(settings.redis_url)
        return RedisHotStore(
            client,
            namespace=settings.memory_namespace,
            ttl_seconds=settings.memory_session_ttl_seconds,
        )
    raise MemoryConfigurationError(f"unsupported hot memory backend: {backend!r}")

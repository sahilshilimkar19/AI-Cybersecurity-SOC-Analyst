"""Integration tests for the Redis hot memory tier.

Requires a reachable Redis specified by ``SOC_TEST_REDIS_URL``; skipped otherwise.
"""

import os
from collections.abc import Iterator
from uuid import uuid4

import pytest
import redis

from config.settings import Settings
from memory.durable import InMemoryDurableStore
from memory.hot import RedisHotStore, build_hot_store
from memory.session import SessionMemory
from models.memory import MemoryEntry


@pytest.fixture
def hot_store() -> Iterator[RedisHotStore]:
    url = os.environ.get("SOC_TEST_REDIS_URL")
    if not url:
        pytest.skip("SOC_TEST_REDIS_URL not set; skipping Redis integration tests")

    client = redis.Redis.from_url(url)
    try:
        client.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"redis not reachable: {exc}")
    client.flushdb()
    yield RedisHotStore(client, namespace="soctest:mem", ttl_seconds=60)
    client.flushdb()


def test_set_and_get_round_trip(hot_store: RedisHotStore) -> None:
    investigation_id = uuid4()
    hot_store.set(investigation_id, MemoryEntry(key="verdict", value={"v": "benign"}, source="n"))

    entry = hot_store.get(investigation_id, "verdict")
    assert entry is not None
    assert entry.value == {"v": "benign"}
    assert entry.source == "n"


def test_get_missing_returns_none(hot_store: RedisHotStore) -> None:
    assert hot_store.get(uuid4(), "nope") is None


def test_get_all_returns_the_investigation_working_set(hot_store: RedisHotStore) -> None:
    investigation_id = uuid4()
    hot_store.set(investigation_id, MemoryEntry(key="a", value={"v": 1}, source="n"))
    hot_store.set(investigation_id, MemoryEntry(key="b", value={"v": 2}, source="n"))

    assert {entry.key for entry in hot_store.get_all(investigation_id)} == {"a", "b"}


def test_entries_are_scoped_per_investigation(hot_store: RedisHotStore) -> None:
    first, second = uuid4(), uuid4()
    hot_store.set(first, MemoryEntry(key="a", value={"v": 1}, source="n"))

    assert hot_store.get_all(second) == []


def test_clear_removes_only_that_investigation(hot_store: RedisHotStore) -> None:
    first, second = uuid4(), uuid4()
    hot_store.set(first, MemoryEntry(key="a", value={"v": 1}, source="n"))
    hot_store.set(second, MemoryEntry(key="a", value={"v": 2}, source="n"))

    hot_store.clear(first)

    assert hot_store.get_all(first) == []
    assert len(hot_store.get_all(second)) == 1


def test_factory_builds_a_redis_hot_store() -> None:
    url = os.environ.get("SOC_TEST_REDIS_URL")
    if not url:
        pytest.skip("SOC_TEST_REDIS_URL not set; skipping Redis integration tests")

    store = build_hot_store(Settings(memory_hot_backend="redis", redis_url=url))
    assert isinstance(store, RedisHotStore)

    investigation_id = uuid4()
    store.set(investigation_id, MemoryEntry(key="a", value={"v": 1}, source="n"))
    assert store.get(investigation_id, "a") is not None
    store.clear(investigation_id)


def test_two_tier_session_survives_a_flushed_cache(hot_store: RedisHotStore) -> None:
    """Losing Redis costs a rebuild, not data."""
    durable = InMemoryDurableStore()
    investigation_id = uuid4()
    session = SessionMemory(hot=hot_store, durable=durable)
    session.write(investigation_id, "verdict", {"v": "malicious"}, source="threat_detector")

    hot_store.clear(investigation_id)

    entry = session.read(investigation_id, "verdict")
    assert entry is not None
    assert entry.value == {"v": "malicious"}

"""Tests for two-tier session memory: write-through, fallback, and rebuild."""

from uuid import UUID, uuid4

import pytest

from memory.durable import InMemoryDurableStore
from memory.hot import InMemoryHotStore
from memory.session import SessionMemory
from models.memory import MemoryEntry


@pytest.fixture
def hot() -> InMemoryHotStore:
    return InMemoryHotStore()


@pytest.fixture
def durable() -> InMemoryDurableStore:
    return InMemoryDurableStore()


@pytest.fixture
def session(hot: InMemoryHotStore, durable: InMemoryDurableStore) -> SessionMemory:
    return SessionMemory(hot=hot, durable=durable)


def test_write_is_write_through_to_both_tiers(
    session: SessionMemory, hot: InMemoryHotStore, durable: InMemoryDurableStore
) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "verdict", {"value": "malicious"}, source="threat_detector")

    assert hot.get(investigation_id, "verdict") is not None
    assert durable.latest(investigation_id, "verdict") is not None


def test_read_is_served_from_the_hot_tier(session: SessionMemory) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "verdict", {"value": "benign"}, source="node")

    entry = session.read(investigation_id, "verdict")
    assert entry is not None
    assert entry.value == {"value": "benign"}
    assert session.stats.hits == 1
    assert session.stats.misses == 0


def test_read_falls_back_to_durable_and_repopulates_cache(
    session: SessionMemory, hot: InMemoryHotStore
) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "verdict", {"value": "benign"}, source="node")

    hot.clear(investigation_id)  # simulate TTL expiry / Redis eviction

    entry = session.read(investigation_id, "verdict")
    assert entry is not None
    assert entry.value == {"value": "benign"}
    assert session.stats.misses == 1
    # The cache was repopulated by the fallback read.
    assert hot.get(investigation_id, "verdict") is not None


def test_read_missing_key_returns_none(session: SessionMemory) -> None:
    assert session.read(uuid4(), "nope") is None


def test_writes_append_revisions_preserving_provenance(session: SessionMemory) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "verdict", {"value": "suspicious"}, source="first_pass")
    session.write(investigation_id, "verdict", {"value": "malicious"}, source="second_pass")

    history = session.history(investigation_id, "verdict")
    assert [entry.revision for entry in history] == [1, 2]
    assert [entry.source for entry in history] == ["first_pass", "second_pass"]
    # What the earlier node saw is still inspectable.
    assert history[0].value == {"value": "suspicious"}

    current = session.read(investigation_id, "verdict")
    assert current is not None
    assert current.value == {"value": "malicious"}


def test_read_all_returns_the_working_set(session: SessionMemory) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "b", {"v": 2}, source="node")
    session.write(investigation_id, "a", {"v": 1}, source="node")

    entries = session.read_all(investigation_id)
    assert [entry.key for entry in entries] == ["a", "b"]


def test_rebuild_restores_hot_tier_from_durable(
    session: SessionMemory, hot: InMemoryHotStore
) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "a", {"v": 1}, source="node")
    session.write(investigation_id, "b", {"v": 2}, source="node")

    hot.clear(investigation_id)
    rebuilt = session.rebuild(investigation_id)

    assert [entry.key for entry in rebuilt] == ["a", "b"]
    assert len(hot.get_all(investigation_id)) == 2
    assert session.stats.recoveries == 1


def test_investigation_survives_a_worker_restart(durable: InMemoryDurableStore) -> None:
    """A new process with a cold cache still sees the whole investigation."""
    investigation_id = uuid4()
    before_restart = SessionMemory(hot=InMemoryHotStore(), durable=durable)
    before_restart.write(investigation_id, "timeline", {"events": 3}, source="log_analyzer")
    before_restart.write(investigation_id, "verdict", {"value": "malicious"}, source="threat")

    # New worker: fresh in-process hot tier, same durable tier.
    after_restart = SessionMemory(hot=InMemoryHotStore(), durable=durable)
    entries = after_restart.read_all(investigation_id)

    assert {entry.key for entry in entries} == {"timeline", "verdict"}
    verdict = after_restart.read(investigation_id, "verdict")
    assert verdict is not None
    assert verdict.value == {"value": "malicious"}


def test_read_all_on_cold_cache_rebuilds(session: SessionMemory, hot: InMemoryHotStore) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "a", {"v": 1}, source="node")
    hot.clear(investigation_id)

    entries = session.read_all(investigation_id)
    assert len(entries) == 1
    assert session.stats.recoveries == 1


def test_hot_write_failure_does_not_lose_the_durable_write(
    durable: InMemoryDurableStore,
) -> None:
    class FailingHotStore(InMemoryHotStore):
        def set(self, investigation_id: UUID, entry: MemoryEntry) -> None:
            raise ConnectionError("redis down")

    investigation_id = uuid4()
    session = SessionMemory(hot=FailingHotStore(), durable=durable)

    # The write succeeds despite the cache being unavailable...
    session.write(investigation_id, "verdict", {"value": "benign"}, source="node")
    # ...and the fact is durably recorded.
    assert durable.latest(investigation_id, "verdict") is not None


def test_evict_hot_keeps_durable_memory(
    session: SessionMemory, hot: InMemoryHotStore, durable: InMemoryDurableStore
) -> None:
    investigation_id = uuid4()
    session.write(investigation_id, "a", {"v": 1}, source="node")

    session.evict_hot(investigation_id)

    assert hot.get_all(investigation_id) == []
    assert durable.latest(investigation_id, "a") is not None
    assert session.stats.evictions == 1

"""Tests for working memory: budget enforcement, eviction, and rebuild."""

from memory.working import WorkingMemory
from models.memory import MemoryEntry


def test_write_and_read_round_trip() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=100)
    working.write("finding", {"verdict": "suspicious"}, source="threat_detector")

    entry = working.read("finding")
    assert entry is not None
    assert entry.value == {"verdict": "suspicious"}
    assert entry.source == "threat_detector"


def test_read_records_hits_and_misses() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=100)
    working.write("a", {"v": 1}, source="node")

    working.read("a")
    working.read("missing")

    assert working.stats.hits == 1
    assert working.stats.misses == 1
    assert working.stats.hit_ratio == 0.5


def test_entry_cap_evicts_oldest_first() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=2)
    working.write("first", {"v": 1}, source="node")
    working.write("second", {"v": 2}, source="node")
    working.write("third", {"v": 3}, source="node")

    keys = [entry.key for entry in working.entries()]
    assert keys == ["second", "third"]
    assert working.stats.evictions == 1


def test_eviction_produces_a_reference_summary() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=1)
    working.write("evicted", {"v": 1}, source="log_analyzer")
    working.write("kept", {"v": 2}, source="log_analyzer")

    assert len(working.summaries) == 1
    # The evicted key remains resolvable by reference.
    assert "evicted" in working.summaries[0]


def test_token_budget_evicts_until_it_fits() -> None:
    working = WorkingMemory(token_budget=60, max_entries=100)
    for index in range(6):
        working.write(f"key{index}", {"blob": "x" * 200}, source="node")

    assert working.estimated_tokens() <= 60 or len(working.entries()) == 1
    assert working.stats.evictions > 0


def test_budget_never_empties_the_scratchpad() -> None:
    # A single oversized entry is the caller's problem to split; memory must not
    # silently hand an agent an empty context.
    working = WorkingMemory(token_budget=5, max_entries=100)
    working.write("huge", {"blob": "x" * 5_000}, source="node")

    assert len(working.entries()) == 1


def test_load_rebuilds_from_session_memory() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=100)
    working.load(
        [
            MemoryEntry(key="a", value={"v": 1}, source="session"),
            MemoryEntry(key="b", value={"v": 2}, source="session"),
        ]
    )

    assert {entry.key for entry in working.entries()} == {"a", "b"}
    assert working.stats.recoveries == 1


def test_clear_discards_everything() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=1)
    working.write("a", {"v": 1}, source="node")
    working.write("b", {"v": 2}, source="node")
    working.clear()

    assert working.entries() == []
    assert working.summaries == []


def test_estimated_tokens_counts_entries_and_summaries() -> None:
    working = WorkingMemory(token_budget=10_000, max_entries=100)
    assert working.estimated_tokens() == 0
    working.write("a", {"v": "x" * 100}, source="node")
    assert working.estimated_tokens() > 0

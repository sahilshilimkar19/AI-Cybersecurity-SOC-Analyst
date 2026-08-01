"""Tests for the knowledge tier's read-only boundary.

Knowledge memory is separated from investigation data so untrusted, potentially
attacker-controlled input can never mutate what agents reason from (invariant #3).
"""

import pytest

from memory.errors import MemoryAccessError
from memory.knowledge import (
    InMemoryKnowledgeMemory,
    UnavailableKnowledgeMemory,
)
from models.memory import KnowledgeChunk


def test_knowledge_is_read_only_to_agents() -> None:
    knowledge = InMemoryKnowledgeMemory()
    with pytest.raises(MemoryAccessError):
        knowledge.write({"content": "injected instruction"})


def test_unavailable_tier_also_refuses_writes() -> None:
    with pytest.raises(MemoryAccessError):
        UnavailableKnowledgeMemory().write({"content": "x"})


def test_write_refusal_names_the_only_legitimate_writer() -> None:
    with pytest.raises(MemoryAccessError, match="RAG ingestion"):
        UnavailableKnowledgeMemory().write({})


def test_unavailable_tier_reports_itself_and_returns_nothing() -> None:
    knowledge = UnavailableKnowledgeMemory()
    assert knowledge.is_available is False
    assert knowledge.search("log4j") == []


def test_in_memory_tier_searches_its_corpus() -> None:
    knowledge = InMemoryKnowledgeMemory(
        [
            KnowledgeChunk(chunk_id="c1", content="Log4Shell affects Log4j 2.x", source="nvd"),
            KnowledgeChunk(chunk_id="c2", content="ATT&CK T1059 command execution", source="mitre"),
        ]
    )
    assert knowledge.is_available is True

    results = knowledge.search("log4j")
    assert len(results) == 1
    assert results[0].chunk_id == "c1"


def test_search_respects_the_limit() -> None:
    knowledge = InMemoryKnowledgeMemory(
        [
            KnowledgeChunk(chunk_id=f"c{index}", content="cve detail", source="nvd")
            for index in range(10)
        ]
    )
    assert len(knowledge.search("cve", limit=3)) == 3

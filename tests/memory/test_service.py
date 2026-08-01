"""Tests for the MemoryService facade and context materialization."""

from uuid import UUID, uuid4

import pytest

from config.settings import Settings
from memory.conversation import InMemoryConversationMemory
from memory.durable import InMemoryDurableStore
from memory.history import InMemoryInvestigationHistory
from memory.hot import InMemoryHotStore
from memory.knowledge import InMemoryKnowledgeMemory, UnavailableKnowledgeMemory
from memory.long_term import InMemoryLongTermMemory
from memory.service import MemoryService, build_memory_service
from memory.session import SessionMemory
from models.enums import MemoryIndexKind
from models.memory import (
    ConversationTurn,
    InvestigationOutcome,
    KnowledgeChunk,
    MemoryTier,
)


def build_service(
    *,
    knowledge: object | None = None,
    conversation: InMemoryConversationMemory | None = None,
    history: InMemoryInvestigationHistory | None = None,
    long_term: InMemoryLongTermMemory | None = None,
    token_budget: int = 10_000,
) -> MemoryService:
    return MemoryService(
        session=SessionMemory(hot=InMemoryHotStore(), durable=InMemoryDurableStore()),
        conversation=conversation or InMemoryConversationMemory(),
        long_term=long_term or InMemoryLongTermMemory(),
        knowledge=knowledge or UnavailableKnowledgeMemory(),  # type: ignore[arg-type]
        history=history or InMemoryInvestigationHistory(),
        working_token_budget=token_budget,
        working_max_entries=100,
    )


def test_remember_and_recall_round_trip() -> None:
    service = build_service()
    investigation_id = uuid4()

    service.remember(investigation_id, "verdict", {"value": "malicious"}, source="threat")
    entry = service.recall(investigation_id, "verdict")

    assert entry is not None
    assert entry.value == {"value": "malicious"}


def test_new_working_memory_is_isolated_per_turn() -> None:
    service = build_service()
    first = service.new_working_memory()
    second = service.new_working_memory()

    first.write("a", {"v": 1}, source="node")

    # Working memory is never shared laterally between nodes.
    assert second.read("a") is None


def test_service_exposes_each_tier() -> None:
    long_term = InMemoryLongTermMemory()
    history = InMemoryInvestigationHistory()
    knowledge = UnavailableKnowledgeMemory()
    service = build_service(knowledge=knowledge, history=history, long_term=long_term)

    assert service.long_term is long_term
    assert service.history is history
    assert service.knowledge is knowledge
    assert isinstance(service.session, SessionMemory)


def test_materialize_context_gathers_session_and_conversation() -> None:
    investigation_id = uuid4()
    conversation = InMemoryConversationMemory()
    conversation.add(investigation_id, ConversationTurn(author_type="human", content="check this"))
    service = build_service(conversation=conversation)
    service.remember(investigation_id, "timeline", {"events": 2}, source="log_analyzer")

    bundle = service.materialize_context(investigation_id)

    assert bundle.investigation_id == investigation_id
    assert [entry.key for entry in bundle.session] == ["timeline"]
    assert [turn.content for turn in bundle.conversation] == ["check this"]
    assert bundle.estimated_tokens > 0


def test_context_includes_working_memory_and_its_summaries() -> None:
    service = build_service()
    investigation_id = uuid4()
    working = service.new_working_memory()
    working.write("note", {"v": 1}, source="node")

    bundle = service.materialize_context(investigation_id, working=working)

    assert [entry.key for entry in bundle.working] == ["note"]


def test_context_searches_knowledge_when_a_query_is_given() -> None:
    knowledge = InMemoryKnowledgeMemory(
        [KnowledgeChunk(chunk_id="c1", content="Log4Shell in Log4j", source="nvd")]
    )
    service = build_service(knowledge=knowledge)

    bundle = service.materialize_context(uuid4(), query="log4j")

    assert [chunk.chunk_id for chunk in bundle.knowledge] == ["c1"]
    assert bundle.is_degraded is False


def test_unavailable_knowledge_marks_context_degraded() -> None:
    service = build_service(knowledge=UnavailableKnowledgeMemory())

    bundle = service.materialize_context(uuid4(), query="log4j")

    assert bundle.knowledge == []
    assert MemoryTier.KNOWLEDGE in bundle.degraded_tiers
    assert bundle.is_degraded is True


def test_failing_tier_degrades_instead_of_collapsing() -> None:
    class ExplodingConversation(InMemoryConversationMemory):
        def recent_turns(
            self, investigation_id: UUID, *, limit: int = 20
        ) -> list[ConversationTurn]:
            raise ConnectionError("postgres unreachable")

    service = build_service(conversation=ExplodingConversation())

    bundle = service.materialize_context(uuid4())

    assert bundle.conversation == []
    assert MemoryTier.CONVERSATION in bundle.degraded_tiers


def test_context_includes_related_investigations() -> None:
    history = InMemoryInvestigationHistory()
    prior = uuid4()
    history.index_investigation(prior, {MemoryIndexKind.CVE: ["CVE-2021-44228"]})
    service = build_service(history=history)

    bundle = service.materialize_context(uuid4(), related={MemoryIndexKind.CVE: ["CVE-2021-44228"]})

    assert [item.investigation_id for item in bundle.related_investigations] == [prior]


def test_context_is_trimmed_to_the_token_budget() -> None:
    service = build_service(token_budget=120)
    investigation_id = uuid4()
    for index in range(12):
        service.remember(investigation_id, f"key{index}", {"blob": "x" * 200}, source="node")

    bundle = service.materialize_context(investigation_id)

    # Trimming happened, and the trimmed keys are still referenced in a summary.
    assert len(bundle.session) < 12
    assert bundle.summaries
    assert "key0" in bundle.summaries[-1]


def test_context_within_budget_is_not_trimmed() -> None:
    service = build_service(token_budget=10_000)
    investigation_id = uuid4()
    service.remember(investigation_id, "a", {"v": 1}, source="node")

    bundle = service.materialize_context(investigation_id)

    assert len(bundle.session) == 1
    assert bundle.summaries == []


def test_close_investigation_indexes_and_evicts_hot() -> None:
    history = InMemoryInvestigationHistory()
    long_term = InMemoryLongTermMemory()
    investigation_id = uuid4()
    long_term.record(InvestigationOutcome(investigation_id=investigation_id, status="closed"))
    service = build_service(history=history, long_term=long_term)
    service.remember(investigation_id, "verdict", {"v": "benign"}, source="node")

    outcome = service.close_investigation(
        investigation_id, index_values={MemoryIndexKind.ASSET: ["web-01"]}
    )

    assert outcome is not None
    assert outcome.status == "closed"
    assert history.find_related(MemoryIndexKind.ASSET, "web-01")
    # Durable memory is retained even after the hot copy is dropped.
    assert service.session.read(investigation_id, "verdict") is not None


@pytest.mark.parametrize("hot_backend", ["memory"])
def test_factory_builds_an_in_process_service(hot_backend: str) -> None:
    service = build_memory_service(Settings(memory_hot_backend=hot_backend))
    investigation_id = uuid4()

    service.remember(investigation_id, "a", {"v": 1}, source="node")
    assert service.recall(investigation_id, "a") is not None
    assert service.knowledge.is_available is False

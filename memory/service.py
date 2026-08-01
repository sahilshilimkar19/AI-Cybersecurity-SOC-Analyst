"""The memory layer's public face (EDS §3.4).

Agents never touch a store directly: they ask this service for context and write
back through it. That indirection is what lets the tiers, their backends, and
their eviction policies change without touching a single agent.

Its central operation is :meth:`MemoryService.materialize_context` — assemble
everything an agent turn should see, within a token budget, degrading tier by
tier rather than failing the investigation when a store is unreachable.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any
from uuid import UUID

from config.logging import get_logger
from memory.conversation import InMemoryConversationMemory, SqlConversationMemory
from memory.durable import InMemoryDurableStore, SqlDurableMemoryStore
from memory.history import InMemoryInvestigationHistory, SqlInvestigationHistory
from memory.hot import build_hot_store
from memory.knowledge import UnavailableKnowledgeMemory
from memory.long_term import InMemoryLongTermMemory, SqlLongTermMemory
from memory.session import SessionMemory
from memory.summarization import ReferenceSummarizer, estimate_entry_tokens, estimate_tokens
from memory.working import WorkingMemory
from models.memory import ContextBundle, MemoryTier

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session

    from config.settings import Settings
    from memory.conversation import ConversationMemory
    from memory.history import InvestigationHistoryMemory
    from memory.knowledge import KnowledgeMemory
    from memory.long_term import LongTermMemory
    from memory.summarization import Summarizer
    from models.enums import MemoryIndexKind
    from models.memory import InvestigationOutcome, MemoryEntry, RelatedInvestigation

_logger = get_logger(__name__)


class MemoryService:
    """Composed access to every memory tier, plus context materialization."""

    def __init__(
        self,
        *,
        session: SessionMemory,
        conversation: ConversationMemory,
        long_term: LongTermMemory,
        knowledge: KnowledgeMemory,
        history: InvestigationHistoryMemory,
        summarizer: Summarizer | None = None,
        working_token_budget: int,
        working_max_entries: int,
    ) -> None:
        self._session = session
        self._conversation = conversation
        self._long_term = long_term
        self._knowledge = knowledge
        self._history = history
        self._summarizer: Summarizer = summarizer or ReferenceSummarizer()
        self._working_token_budget = working_token_budget
        self._working_max_entries = working_max_entries

    # --- Tier access ------------------------------------------------------

    @property
    def session(self) -> SessionMemory:
        """Investigation-scoped two-tier memory."""
        return self._session

    @property
    def knowledge(self) -> KnowledgeMemory:
        """Curated reference knowledge (read-only)."""
        return self._knowledge

    @property
    def long_term(self) -> LongTermMemory:
        """Cross-investigation institutional record."""
        return self._long_term

    @property
    def history(self) -> InvestigationHistoryMemory:
        """Cross-investigation recall index."""
        return self._history

    def new_working_memory(self) -> WorkingMemory:
        """Create a fresh per-turn scratchpad, sized by configuration.

        A new instance per turn is the point: working memory is never shared
        laterally between nodes.
        """
        return WorkingMemory(
            token_budget=self._working_token_budget,
            max_entries=self._working_max_entries,
            summarizer=self._summarizer,
        )

    # --- Operations -------------------------------------------------------

    def remember(
        self, investigation_id: UUID, key: str, value: dict[str, Any], *, source: str
    ) -> MemoryEntry:
        """Record a fact in session memory (write-through, provenance preserved)."""
        return self._session.write(investigation_id, key, value, source=source)

    def recall(self, investigation_id: UUID, key: str) -> MemoryEntry | None:
        """Read a single session-memory key."""
        return self._session.read(investigation_id, key)

    def close_investigation(
        self,
        investigation_id: UUID,
        *,
        index_values: Mapping[MemoryIndexKind, Sequence[str]] | None = None,
    ) -> InvestigationOutcome | None:
        """Retire an investigation from memory.

        Indexes it for future recall, drops the hot copy, and returns its recorded
        outcome. Durable session memory is retained for audit and archival.
        """
        if index_values:
            self._history.index_investigation(investigation_id, index_values)
        self._session.evict_hot(investigation_id)
        return self._long_term.outcome_for(investigation_id)

    def materialize_context(
        self,
        investigation_id: UUID,
        *,
        query: str | None = None,
        working: WorkingMemory | None = None,
        conversation_limit: int = 20,
        knowledge_limit: int = 5,
        related: Mapping[MemoryIndexKind, Sequence[str]] | None = None,
        token_budget: int | None = None,
    ) -> ContextBundle:
        """Assemble the context for one agent turn.

        Every tier is read defensively: an unreachable tier is recorded in
        ``degraded_tiers`` and the turn proceeds with what is available, rather
        than collapsing the investigation (invariant #6).
        """
        budget = token_budget or self._working_token_budget
        degraded: list[MemoryTier] = []

        session_entries = self._read_tier(
            MemoryTier.SESSION, degraded, lambda: self._session.read_all(investigation_id), []
        )
        conversation_turns = self._read_tier(
            MemoryTier.CONVERSATION,
            degraded,
            lambda: self._conversation.recent_turns(investigation_id, limit=conversation_limit),
            [],
        )

        knowledge_chunks = []
        if query:
            if self._knowledge.is_available:
                knowledge_chunks = self._read_tier(
                    MemoryTier.KNOWLEDGE,
                    degraded,
                    lambda: self._knowledge.search(query, limit=knowledge_limit),
                    [],
                )
            else:
                degraded.append(MemoryTier.KNOWLEDGE)

        related_investigations: list[RelatedInvestigation] = []
        if related:
            for kind, values in related.items():
                for value in values:
                    related_investigations.extend(
                        self._read_tier(
                            MemoryTier.INVESTIGATION_HISTORY,
                            degraded,
                            partial(self._history.find_related, kind, value),
                            [],
                        )
                    )

        working_entries = working.entries() if working is not None else []
        summaries = list(working.summaries) if working is not None else []

        bundle = ContextBundle(
            investigation_id=investigation_id,
            working=working_entries,
            session=session_entries,
            conversation=conversation_turns,
            knowledge=knowledge_chunks,
            related_investigations=related_investigations,
            summaries=summaries,
            degraded_tiers=degraded,
        )
        return self._fit_to_budget(bundle, budget)

    def _read_tier(
        self,
        tier: MemoryTier,
        degraded: list[MemoryTier],
        read: Callable[[], list[Any]],
        fallback: list[Any],
    ) -> list[Any]:
        """Read one tier, recording degradation instead of propagating a failure."""
        try:
            return read()
        except Exception:
            if tier not in degraded:
                degraded.append(tier)
            _logger.warning("memory_tier_unavailable", tier=str(tier), exc_info=True)
            return list(fallback)

    def _fit_to_budget(self, bundle: ContextBundle, budget: int) -> ContextBundle:
        """Trim session entries oldest-first until the bundle fits its token budget.

        Trimmed entries are replaced by a reference summary, so their identifiers
        stay resolvable from durable memory — nothing is silently dropped.
        """
        fixed = (
            sum(estimate_tokens(turn.content) for turn in bundle.conversation)
            + sum(estimate_tokens(chunk.content) for chunk in bundle.knowledge)
            + sum(estimate_entry_tokens(entry) for entry in bundle.working)
            + sum(estimate_tokens(text) for text in bundle.summaries)
        )

        retained = list(bundle.session)
        trimmed: list[MemoryEntry] = []
        while retained and fixed + sum(estimate_entry_tokens(e) for e in retained) > budget:
            trimmed.append(retained.pop(0))

        summaries = list(bundle.summaries)
        if trimmed:
            summary = self._summarizer.summarize(trimmed)
            if summary:
                summaries.append(summary)
            _logger.info(
                "context_trimmed_to_budget",
                investigation_id=str(bundle.investigation_id),
                trimmed=len(trimmed),
                budget=budget,
            )

        total = (
            fixed
            + sum(estimate_entry_tokens(entry) for entry in retained)
            + sum(estimate_tokens(text) for text in summaries[len(bundle.summaries) :])
        )
        return bundle.model_copy(
            update={"session": retained, "summaries": summaries, "estimated_tokens": total}
        )


def build_memory_service(
    settings: Settings,
    *,
    session_scope: Callable[[], AbstractContextManager[Session]] | None = None,
    knowledge: KnowledgeMemory | None = None,
) -> MemoryService:
    """Compose the memory service from configuration.

    With a ``session_scope`` the durable tiers are PostgreSQL-backed; without one
    the service is fully in-process, which is what tests and local runs use.

    ``knowledge`` is injected rather than constructed here so the memory layer
    does not depend on the RAG pipeline: the composition root supplies the
    RAG-backed tier, and without one the placeholder reports itself unavailable.
    """
    hot = build_hot_store(settings)
    knowledge_tier: KnowledgeMemory = knowledge or UnavailableKnowledgeMemory()

    if session_scope is None:
        return MemoryService(
            session=SessionMemory(hot=hot, durable=InMemoryDurableStore()),
            conversation=InMemoryConversationMemory(),
            long_term=InMemoryLongTermMemory(),
            knowledge=knowledge_tier,
            history=InMemoryInvestigationHistory(),
            working_token_budget=settings.memory_working_token_budget,
            working_max_entries=settings.memory_working_max_entries,
        )

    return MemoryService(
        session=SessionMemory(hot=hot, durable=SqlDurableMemoryStore(session_scope)),
        conversation=SqlConversationMemory(session_scope),
        long_term=SqlLongTermMemory(session_scope),
        knowledge=knowledge_tier,
        history=SqlInvestigationHistory(session_scope),
        working_token_budget=settings.memory_working_token_budget,
        working_max_entries=settings.memory_working_max_entries,
    )

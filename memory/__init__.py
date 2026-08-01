"""Memory layer — tiered memory managers behind clean interfaces.

Six tiers (SAD §5 / EDS §7), each with its own lifetime, backing store, and
eviction rule:

* **working** — per-turn scratch space, bounded by a token budget and evicted
  through the summarizer; rebuilt from session memory on retry.
* **session** — one investigation, two-tier (Redis hot + PostgreSQL durable);
  write-through with the durable tier as the source of truth, so an investigation
  survives a worker restart.
* **conversation** — the human-in-the-loop thread, read back for context.
* **long-term** — the institutional record of closed investigations.
* **knowledge** — the curated reference corpus, **read-only to agents** (a
  prompt-injection safety boundary); written only by RAG ingestion.
* **investigation history** — cross-investigation recall by asset/IoC/technique/CVE.

Agents never touch a store directly; they go through :class:`MemoryService`.

See docs/ENGINEERING_DESIGN_SPEC.md §7 and docs/adr/0005-memory-layer.md.
"""

from __future__ import annotations

from memory.conversation import (
    ConversationMemory,
    InMemoryConversationMemory,
    SqlConversationMemory,
)
from memory.durable import DurableMemoryStore, InMemoryDurableStore, SqlDurableMemoryStore
from memory.errors import (
    CorruptMemoryError,
    MemoryAccessError,
    MemoryConfigurationError,
    MemoryError,
)
from memory.history import (
    InMemoryInvestigationHistory,
    InvestigationHistoryMemory,
    SqlInvestigationHistory,
)
from memory.hot import (
    HotBackend,
    HotMemoryStore,
    InMemoryHotStore,
    RedisHotStore,
    build_hot_store,
)
from memory.knowledge import (
    InMemoryKnowledgeMemory,
    KnowledgeMemory,
    ReadOnlyKnowledgeMemory,
    UnavailableKnowledgeMemory,
)
from memory.long_term import InMemoryLongTermMemory, LongTermMemory, SqlLongTermMemory
from memory.service import MemoryService, build_memory_service
from memory.session import SessionMemory
from memory.summarization import ReferenceSummarizer, Summarizer, estimate_tokens
from memory.working import WorkingMemory

__all__ = [
    "ConversationMemory",
    "CorruptMemoryError",
    "DurableMemoryStore",
    "HotBackend",
    "HotMemoryStore",
    "InMemoryConversationMemory",
    "InMemoryDurableStore",
    "InMemoryHotStore",
    "InMemoryInvestigationHistory",
    "InMemoryKnowledgeMemory",
    "InMemoryLongTermMemory",
    "InvestigationHistoryMemory",
    "KnowledgeMemory",
    "LongTermMemory",
    "MemoryAccessError",
    "MemoryConfigurationError",
    "MemoryError",
    "MemoryService",
    "ReadOnlyKnowledgeMemory",
    "RedisHotStore",
    "ReferenceSummarizer",
    "SessionMemory",
    "SqlConversationMemory",
    "SqlDurableMemoryStore",
    "SqlInvestigationHistory",
    "SqlLongTermMemory",
    "Summarizer",
    "UnavailableKnowledgeMemory",
    "WorkingMemory",
    "build_hot_store",
    "build_memory_service",
    "estimate_tokens",
]

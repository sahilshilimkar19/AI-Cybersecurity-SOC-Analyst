"""Pluggable checkpointer for the investigation graph.

State is checkpointed after every node transition; checkpoints are the unit of
resume and rollback (EDS §5). The backend is selected by configuration, mirroring
the object-store and session-store patterns (ADR 0002/0003).

Only the in-memory backend ships in the LangGraph Core sprint. A durable Postgres
checkpointer is introduced with the two-tier durable memory in the Memory sprint
(EDS §7), so the durable path lands together with the rest of the durable tier.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from langgraph.checkpoint.memory import InMemorySaver

from graph.errors import GraphConfigurationError

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver

    from config.settings import Settings


class CheckpointBackend(StrEnum):
    """Supported checkpoint storage backends."""

    MEMORY = "memory"
    # POSTGRES is added with the durable memory tier in the Memory sprint.


def build_checkpointer(settings: Settings) -> BaseCheckpointSaver:
    """Build the checkpointer for the configured backend (fail-fast on unknown)."""
    backend = settings.graph_checkpoint_backend
    if backend == CheckpointBackend.MEMORY:
        return InMemorySaver()
    raise GraphConfigurationError(f"unsupported checkpoint backend: {backend!r}")

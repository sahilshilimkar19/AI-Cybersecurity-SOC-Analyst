"""Pluggable checkpointer for the investigation graph.

State is checkpointed after every node transition; checkpoints are the unit of
resume and rollback (EDS §5). The backend is selected by configuration, mirroring
the object-store and session-store patterns (ADR 0002/0003).

Two backends ship: ``memory`` (per-process, for tests and local runs) and
``postgres``, added with the durable memory tier so a paused investigation
survives a worker restart (invariant #6).

The Postgres checkpointer owns its own tables and creates them via ``setup()``.
They are deliberately outside Alembic — LangGraph migrates that schema itself —
and are excluded from autogenerate comparison in the migration environment.
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
    POSTGRES = "postgres"


def to_psycopg_dsn(database_url: str) -> str:
    """Convert a SQLAlchemy URL to the plain DSN psycopg expects.

    The application configures one database URL in SQLAlchemy form
    (``postgresql+psycopg://``); the checkpointer connects with psycopg directly.
    """
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def build_checkpointer(settings: Settings) -> BaseCheckpointSaver:
    """Build the checkpointer for the configured backend (fail-fast on unknown).

    The Postgres saver holds a long-lived connection owned by the process; the
    caller keeps the returned saver for the application's lifetime.
    """
    backend = settings.graph_checkpoint_backend
    if backend == CheckpointBackend.MEMORY:
        return InMemorySaver()
    if backend == CheckpointBackend.POSTGRES:
        import psycopg
        from langgraph.checkpoint.postgres import PostgresSaver

        # autocommit is required: setup() issues DDL that must not sit in an
        # open transaction shared with checkpoint writes.
        connection = psycopg.connect(
            to_psycopg_dsn(settings.database_url),
            autocommit=True,
            row_factory=psycopg.rows.dict_row,
        )
        saver = PostgresSaver(connection)
        saver.setup()
        return saver
    raise GraphConfigurationError(f"unsupported checkpoint backend: {backend!r}")

"""The durable half of session memory — the source of truth (EDS §7).

Writes are **append-only revisions** so provenance survives: the value a node saw
at the time it acted is still there after a later node overwrites the same key.
The hot tier is always rebuildable from here.

The interface is a protocol with a SQL implementation and an in-process
implementation, so the memory managers can be exercised without a database.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from models.memory import MemoryEntry

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session


class DurableMemoryStore(Protocol):
    """Durable, append-only storage for session memory."""

    def append(
        self, *, investigation_id: UUID, key: str, value: dict[str, Any], source: str
    ) -> MemoryEntry: ...
    def latest(self, investigation_id: UUID, key: str) -> MemoryEntry | None: ...
    def latest_all(self, investigation_id: UUID) -> list[MemoryEntry]: ...
    def history(self, investigation_id: UUID, key: str) -> list[MemoryEntry]: ...


class InMemoryDurableStore:
    """In-process durable store for tests and local development."""

    def __init__(self) -> None:
        self._entries: dict[UUID, dict[str, list[MemoryEntry]]] = {}

    def append(
        self, *, investigation_id: UUID, key: str, value: dict[str, Any], source: str
    ) -> MemoryEntry:
        revisions = self._entries.setdefault(investigation_id, {}).setdefault(key, [])
        entry = MemoryEntry(key=key, value=dict(value), source=source, revision=len(revisions) + 1)
        revisions.append(entry)
        return entry

    def latest(self, investigation_id: UUID, key: str) -> MemoryEntry | None:
        revisions = self._entries.get(investigation_id, {}).get(key, [])
        return revisions[-1] if revisions else None

    def latest_all(self, investigation_id: UUID) -> list[MemoryEntry]:
        return [
            revisions[-1]
            for _, revisions in sorted(self._entries.get(investigation_id, {}).items())
            if revisions
        ]

    def history(self, investigation_id: UUID, key: str) -> list[MemoryEntry]:
        return list(self._entries.get(investigation_id, {}).get(key, []))


class SqlDurableMemoryStore:
    """PostgreSQL-backed durable session memory.

    Each operation runs in its own transactional scope supplied by the caller, so
    memory writes never straddle an unrelated transaction.
    """

    def __init__(self, session_scope: Callable[[], AbstractContextManager[Session]]) -> None:
        self._session_scope = session_scope

    @staticmethod
    def _to_entry(row: Any) -> MemoryEntry:
        return MemoryEntry(
            key=row.key,
            value=dict(row.value),
            source=row.source,
            revision=row.revision,
            created_at=row.created_at,
        )

    def append(
        self, *, investigation_id: UUID, key: str, value: dict[str, Any], source: str
    ) -> MemoryEntry:
        from backend.db.repositories.memory import SessionMemoryRepository

        with self._session_scope() as session:
            row = SessionMemoryRepository(session).append(
                investigation_id=investigation_id, key=key, value=value, source=source
            )
            return self._to_entry(row)

    def latest(self, investigation_id: UUID, key: str) -> MemoryEntry | None:
        from backend.db.repositories.memory import SessionMemoryRepository

        with self._session_scope() as session:
            row = SessionMemoryRepository(session).latest(investigation_id, key)
            return self._to_entry(row) if row is not None else None

    def latest_all(self, investigation_id: UUID) -> list[MemoryEntry]:
        from backend.db.repositories.memory import SessionMemoryRepository

        with self._session_scope() as session:
            rows = SessionMemoryRepository(session).latest_for_investigation(investigation_id)
            return [self._to_entry(row) for row in rows]

    def history(self, investigation_id: UUID, key: str) -> list[MemoryEntry]:
        from backend.db.repositories.memory import SessionMemoryRepository

        with self._session_scope() as session:
            rows = SessionMemoryRepository(session).history(investigation_id, key)
            return [self._to_entry(row) for row in rows]

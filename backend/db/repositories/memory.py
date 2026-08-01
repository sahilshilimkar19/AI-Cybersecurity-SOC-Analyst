"""Data access for the durable memory tiers.

Writes are staged and flushed (not committed) so the caller owns the transaction
boundary, consistent with the other repositories.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.orm.memory import InvestigationMemoryIndexEntry, SessionMemoryEntry
from backend.db.repositories.base import Repository
from models.enums import MemoryIndexKind


class SessionMemoryRepository(Repository[SessionMemoryEntry]):
    """Append-only durable session memory, revisioned per key."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, SessionMemoryEntry)

    def append(
        self,
        *,
        investigation_id: UUID,
        key: str,
        value: dict[str, object],
        source: str,
    ) -> SessionMemoryEntry:
        """Append a new revision of ``key`` rather than overwriting the previous one."""
        next_revision = self._next_revision(investigation_id, key)
        return self.add(
            SessionMemoryEntry(
                investigation_id=investigation_id,
                key=key,
                value=dict(value),
                source=source,
                revision=next_revision,
            )
        )

    def _next_revision(self, investigation_id: UUID, key: str) -> int:
        stmt = select(func.max(SessionMemoryEntry.revision)).where(
            SessionMemoryEntry.investigation_id == investigation_id,
            SessionMemoryEntry.key == key,
        )
        current: int | None = self._session.execute(stmt).scalar_one_or_none()
        return (current or 0) + 1

    def latest(self, investigation_id: UUID, key: str) -> SessionMemoryEntry | None:
        """Return the most recent revision of a single key."""
        stmt = (
            select(SessionMemoryEntry)
            .where(
                SessionMemoryEntry.investigation_id == investigation_id,
                SessionMemoryEntry.key == key,
            )
            .order_by(SessionMemoryEntry.revision.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def latest_for_investigation(self, investigation_id: UUID) -> list[SessionMemoryEntry]:
        """Return the most recent revision of every key in an investigation."""
        newest = (
            select(
                SessionMemoryEntry.key.label("key"),
                func.max(SessionMemoryEntry.revision).label("revision"),
            )
            .where(SessionMemoryEntry.investigation_id == investigation_id)
            .group_by(SessionMemoryEntry.key)
            .subquery()
        )
        stmt = (
            select(SessionMemoryEntry)
            .join(
                newest,
                (SessionMemoryEntry.key == newest.c.key)
                & (SessionMemoryEntry.revision == newest.c.revision),
            )
            .where(SessionMemoryEntry.investigation_id == investigation_id)
            .order_by(SessionMemoryEntry.key)
        )
        return list(self._session.execute(stmt).scalars().all())

    def history(self, investigation_id: UUID, key: str) -> Sequence[SessionMemoryEntry]:
        """Return every retained revision of a key, oldest first (provenance trail)."""
        stmt = (
            select(SessionMemoryEntry)
            .where(
                SessionMemoryEntry.investigation_id == investigation_id,
                SessionMemoryEntry.key == key,
            )
            .order_by(SessionMemoryEntry.revision)
        )
        return self._session.execute(stmt).scalars().all()


class InvestigationMemoryIndexRepository(Repository[InvestigationMemoryIndexEntry]):
    """Recall index over closed investigations, keyed by asset/IoC/technique/CVE."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, InvestigationMemoryIndexEntry)

    def index(
        self, *, investigation_id: UUID, kind: MemoryIndexKind, value: str
    ) -> InvestigationMemoryIndexEntry:
        """Record a recall pointer, idempotently (re-indexing is safe)."""
        existing = self._session.execute(
            select(InvestigationMemoryIndexEntry).where(
                InvestigationMemoryIndexEntry.investigation_id == investigation_id,
                InvestigationMemoryIndexEntry.kind == kind,
                InvestigationMemoryIndexEntry.value == value,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        return self.add(
            InvestigationMemoryIndexEntry(investigation_id=investigation_id, kind=kind, value=value)
        )

    def find_investigations(
        self, *, kind: MemoryIndexKind, value: str, limit: int = 20
    ) -> list[UUID]:
        """Return investigations previously indexed under this value ("seen before")."""
        stmt = (
            select(InvestigationMemoryIndexEntry.investigation_id)
            .where(
                InvestigationMemoryIndexEntry.kind == kind,
                InvestigationMemoryIndexEntry.value == value,
            )
            .order_by(InvestigationMemoryIndexEntry.created_at.desc())
            .limit(limit)
        )
        return list(self._session.execute(stmt).scalars().all())

    def entries_for_investigation(
        self, investigation_id: UUID
    ) -> Sequence[InvestigationMemoryIndexEntry]:
        """Return everything an investigation is indexed under."""
        stmt = (
            select(InvestigationMemoryIndexEntry)
            .where(InvestigationMemoryIndexEntry.investigation_id == investigation_id)
            .order_by(InvestigationMemoryIndexEntry.kind, InvestigationMemoryIndexEntry.value)
        )
        return self._session.execute(stmt).scalars().all()

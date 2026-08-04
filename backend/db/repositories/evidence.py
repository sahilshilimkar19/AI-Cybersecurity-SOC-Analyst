"""Data access for normalized log evidence.

Log events are **immutable once written** (EDS §6): they are the forensic record
of what was observed, so this repository appends and reads but never updates.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.orm.evidence import LogEvent
from backend.db.repositories.base import Repository


class LogEventRepository(Repository[LogEvent]):
    """Append-only access to normalized log events."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, LogEvent)

    def add_many(self, events: Sequence[LogEvent]) -> int:
        """Append a batch of events, flushing so ids are assigned."""
        for event in events:
            self._session.add(event)
        self._session.flush()
        return len(events)

    def for_investigation(self, investigation_id: UUID, *, limit: int = 500) -> list[LogEvent]:
        """Return an investigation's events in chronological order."""
        stmt = (
            select(LogEvent)
            .where(LogEvent.investigation_id == investigation_id)
            .order_by(LogEvent.event_time, LogEvent.id)
            .limit(limit)
        )
        return list(self._session.execute(stmt).scalars().all())

    def count_for_investigation(self, investigation_id: UUID) -> int:
        """How many events an investigation has recorded."""
        return len(self.for_investigation(investigation_id, limit=10_000))

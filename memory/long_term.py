"""Long-term memory — the institutional record across investigations (EDS §7).

Persistent and cross-investigation: closed investigations, their verdicts and
outcomes. It is deliberately a **read model over the durable investigation
entities** rather than a second copy of them — the system of record already holds
the verdict, severity, and closure, and duplicating it would create two truths to
keep in sync. "Written on investigation close" is therefore satisfied by the
closure itself; this tier reads it back for analytics and "have we seen this
before?" questions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from models.memory import InvestigationOutcome

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session

    from backend.db.orm.investigation import Investigation


class LongTermMemory(Protocol):
    """Read access to closed-investigation outcomes."""

    def outcome_for(self, investigation_id: UUID) -> InvestigationOutcome | None: ...
    def recent_outcomes(self, *, limit: int = 20) -> list[InvestigationOutcome]: ...


class InMemoryLongTermMemory:
    """In-process long-term memory for tests and local development."""

    def __init__(self) -> None:
        self._outcomes: dict[UUID, InvestigationOutcome] = {}

    def record(self, outcome: InvestigationOutcome) -> None:
        self._outcomes[outcome.investigation_id] = outcome

    def outcome_for(self, investigation_id: UUID) -> InvestigationOutcome | None:
        return self._outcomes.get(investigation_id)

    def recent_outcomes(self, *, limit: int = 20) -> list[InvestigationOutcome]:
        return list(self._outcomes.values())[:limit]


class SqlLongTermMemory:
    """PostgreSQL-backed long-term memory over investigations and their assessments."""

    def __init__(self, session_scope: Callable[[], AbstractContextManager[Session]]) -> None:
        self._session_scope = session_scope

    def outcome_for(self, investigation_id: UUID) -> InvestigationOutcome | None:
        """Return the recorded outcome of a single investigation."""
        from sqlalchemy import select

        from backend.db.orm.investigation import Investigation

        with self._session_scope() as session:
            investigation = session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            ).scalar_one_or_none()
            if investigation is None:
                return None
            return self._build(session, investigation)

    def recent_outcomes(self, *, limit: int = 20) -> list[InvestigationOutcome]:
        """Return the most recently closed investigations."""
        from sqlalchemy import select

        from backend.db.orm.investigation import Investigation
        from models.enums import InvestigationStatus

        with self._session_scope() as session:
            stmt = (
                select(Investigation)
                .where(Investigation.status == InvestigationStatus.CLOSED)
                .order_by(Investigation.closed_at.desc())
                .limit(limit)
            )
            investigations = list(session.execute(stmt).scalars().all())
            return [self._build(session, item) for item in investigations]

    @staticmethod
    def _build(session: Session, investigation: Investigation) -> InvestigationOutcome:
        """Compose an outcome from the investigation and its latest assessment."""
        from sqlalchemy import select

        from backend.db.orm.analysis import ThreatAssessment

        assessment = (
            session.execute(
                select(ThreatAssessment)
                .where(ThreatAssessment.investigation_id == investigation.id)
                .order_by(ThreatAssessment.version.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )

        return InvestigationOutcome(
            investigation_id=investigation.id,
            status=str(investigation.status),
            severity=str(investigation.severity) if investigation.severity else None,
            verdict=str(assessment.verdict) if assessment is not None else None,
            title=investigation.title,
            closed_at=investigation.closed_at,
        )

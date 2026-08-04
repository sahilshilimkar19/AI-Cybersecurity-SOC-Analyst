"""Data access for incident reports.

Reports are **versioned, never overwritten** (EDS §6). Regeneration is a first-
class operation here — a report is reproducible from investigation state — but a
regenerated report is a *new version*, not a replacement. What an analyst
actually read has to remain readable, because that is the document their decision
was made against.

The unique constraint on ``(investigation_id, version)`` enforces that at the
database level rather than by convention, so two concurrent generations cannot
quietly collapse into one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from backend.db.orm.reporting import Report
from backend.db.repositories.base import Repository

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.orm import Session


class ReportRepository(Repository[Report]):
    """Versioned access to an investigation's incident reports."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Report)

    def latest_version(self, investigation_id: UUID) -> int:
        """The highest version recorded, or ``0`` if the report has never run."""
        stmt = select(func.max(Report.version)).where(Report.investigation_id == investigation_id)
        return self._session.execute(stmt).scalar() or 0

    def current(self, investigation_id: UUID) -> Report | None:
        """The most recent report for an investigation."""
        stmt = (
            select(Report)
            .where(Report.investigation_id == investigation_id)
            .order_by(Report.version.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def for_version(self, investigation_id: UUID, version: int) -> Report | None:
        """One generation, so the document a decision rested on stays readable."""
        stmt = select(Report).where(
            Report.investigation_id == investigation_id, Report.version == version
        )
        return self._session.execute(stmt).scalars().first()

    def history(self, investigation_id: UUID, *, limit: int = 50) -> list[Report]:
        """Every report generation, oldest first."""
        stmt = (
            select(Report)
            .where(Report.investigation_id == investigation_id)
            .order_by(Report.version)
            .limit(limit)
        )
        return list(self._session.execute(stmt).scalars().all())

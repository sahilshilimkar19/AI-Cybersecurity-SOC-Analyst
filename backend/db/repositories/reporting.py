"""Data access for incident reports and remediation recommendations.

Both are **versioned, never overwritten** (EDS §6). Regeneration is a first-class
operation here — a report and a plan are reproducible from investigation state —
but a regenerated artifact is a *new version*, not a replacement. What an analyst
actually read has to remain readable, because that is the document their decision
was made against.

For reports the unique constraint on ``(investigation_id, version)`` enforces
that at the database level rather than by convention, so two concurrent
generations cannot quietly collapse into one.

Recommendations additionally carry an approval status that only a human decision
moves off ``PENDING``. This repository can read them by that status, because
"what is waiting on a person" is the query the approval queue is built from.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from backend.db.orm.reporting import Recommendation, Report
from backend.db.repositories.base import Repository
from models.enums import ApprovalStatus

if TYPE_CHECKING:
    from collections.abc import Sequence
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


class RecommendationRepository(Repository[Recommendation]):
    """Versioned access to an investigation's remediation recommendations."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Recommendation)

    def latest_version(self, investigation_id: UUID) -> int:
        """The highest plan version recorded, or ``0`` if none."""
        stmt = select(func.max(Recommendation.version)).where(
            Recommendation.investigation_id == investigation_id
        )
        return self._session.execute(stmt).scalar() or 0

    def add_many(self, recommendations: Sequence[Recommendation]) -> int:
        """Write a plan generation, flushing so ids are assigned."""
        for recommendation in recommendations:
            self._session.add(recommendation)
        self._session.flush()
        return len(recommendations)

    def current(self, investigation_id: UUID) -> list[Recommendation]:
        """The most recent plan generation, most urgent first."""
        version = self.latest_version(investigation_id)
        return self.for_version(investigation_id, version) if version else []

    def for_version(self, investigation_id: UUID, version: int) -> list[Recommendation]:
        """One plan generation, so a superseded plan can be read back whole."""
        stmt = (
            select(Recommendation)
            .where(
                Recommendation.investigation_id == investigation_id,
                Recommendation.version == version,
            )
            .order_by(Recommendation.priority, Recommendation.action)
        )
        return list(self._session.execute(stmt).scalars().all())

    def pending_approval(self, investigation_id: UUID) -> list[Recommendation]:
        """Recommendations still waiting on a human.

        The approval queue is built from this, so it reads the *current* plan
        only: a superseded generation's pending items are historical record, not
        outstanding work.
        """
        return [
            item
            for item in self.current(investigation_id)
            if item.approval_status is ApprovalStatus.PENDING
        ]

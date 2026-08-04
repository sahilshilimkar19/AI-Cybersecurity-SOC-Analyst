"""Data access for threat assessments.

Assessments are **versioned, never overwritten** (EDS §6): an investigation's
understanding changes as evidence arrives, and the record of what was believed —
and when — is exactly what makes a decision defensible afterwards. Superseding an
assessment therefore writes a new row with the next version rather than editing
the previous one, and the soft-delete column marks supersession without erasing
history.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from backend.db.orm.analysis import ThreatAssessment
from backend.db.repositories.base import Repository

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.orm import Session


class ThreatAssessmentRepository(Repository[ThreatAssessment]):
    """Versioned access to an investigation's threat assessments."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, ThreatAssessment)

    def latest_version(self, investigation_id: UUID) -> int:
        """The highest version recorded for an investigation, or ``0`` if none."""
        stmt = select(func.max(ThreatAssessment.version)).where(
            ThreatAssessment.investigation_id == investigation_id
        )
        return self._session.execute(stmt).scalar() or 0

    def current(self, investigation_id: UUID) -> ThreatAssessment | None:
        """The most recent assessment for an investigation."""
        stmt = (
            select(ThreatAssessment)
            .where(ThreatAssessment.investigation_id == investigation_id)
            .order_by(ThreatAssessment.version.desc(), ThreatAssessment.id.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def history(self, investigation_id: UUID, *, limit: int = 50) -> list[ThreatAssessment]:
        """Every assessment recorded for an investigation, oldest first."""
        stmt = (
            select(ThreatAssessment)
            .where(ThreatAssessment.investigation_id == investigation_id)
            .order_by(ThreatAssessment.version, ThreatAssessment.id)
            .limit(limit)
        )
        return list(self._session.execute(stmt).scalars().all())

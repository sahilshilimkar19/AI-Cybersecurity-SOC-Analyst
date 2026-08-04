"""Data access for threat assessments and CVE findings.

Both are **versioned, never overwritten** (EDS §6): an investigation's
understanding changes as evidence arrives, and the record of what was believed —
and when — is exactly what makes a decision defensible afterwards. Superseding a
row therefore writes a new one with the next version rather than editing the
previous one, and the soft-delete column marks supersession without erasing
history.

CVE findings version *per investigation* rather than per CVE, so a re-run
produces one coherent dossier generation rather than a set of rows each at its
own version — "what did we believe on Tuesday" has to be answerable as a whole.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from backend.db.orm.analysis import CveFinding, ThreatAssessment
from backend.db.repositories.base import Repository

if TYPE_CHECKING:
    from collections.abc import Sequence
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


class CveFindingRepository(Repository[CveFinding]):
    """Versioned access to an investigation's CVE findings."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, CveFinding)

    def latest_version(self, investigation_id: UUID) -> int:
        """The highest dossier version recorded, or ``0`` if none."""
        stmt = select(func.max(CveFinding.version)).where(
            CveFinding.investigation_id == investigation_id
        )
        return self._session.execute(stmt).scalar() or 0

    def add_many(self, findings: Sequence[CveFinding]) -> int:
        """Write a dossier generation, flushing so ids are assigned."""
        for finding in findings:
            self._session.add(finding)
        self._session.flush()
        return len(findings)

    def current(self, investigation_id: UUID) -> list[CveFinding]:
        """The most recent dossier generation, worst CVSS first."""
        version = self.latest_version(investigation_id)
        if version == 0:
            return []
        return self.for_version(investigation_id, version)

    def for_version(self, investigation_id: UUID, version: int) -> list[CveFinding]:
        """One dossier generation, so a prior belief can be read back whole."""
        stmt = (
            select(CveFinding)
            .where(
                CveFinding.investigation_id == investigation_id,
                CveFinding.version == version,
            )
            .order_by(CveFinding.cve_id)
        )
        return list(self._session.execute(stmt).scalars().all())

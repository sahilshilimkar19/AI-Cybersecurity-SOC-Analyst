"""Persisting incident reports (invariant #7).

The Incident Reporter *produces* a report; the backend *writes* it — the same
split the evidence, assessment, and vulnerability services make.

Two decisions shape what lands in the table:

* **A report is stored as prose plus its references, and nothing else is
  re-derived at read time.** The rendered document is the artifact; regenerating
  the Markdown from structured fields on every read would let a template change
  silently alter a document someone already signed off on.
* **A report is written as a draft.** Only a human decision promotes it to final
  (invariant #1) — the agent has no authority to declare its own output
  approved, and a `final` status that an agent could set would mean nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.db.orm.reporting import Report
from backend.db.repositories.reporting import ReportRepository
from config.logging import get_logger
from models.enums import ReportStatus

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.orm import Session

    from models.report import IncidentReport

_logger = get_logger(__name__)


def to_report(investigation_id: UUID, report: IncidentReport, *, version: int = 1) -> Report:
    """Map a generated report onto its persistent row."""
    return Report(
        investigation_id=investigation_id,
        executive_summary=report.executive_summary,
        technical_body=report.technical_body,
        citations=[citation.model_dump(mode="json") for citation in report.citations],
        status=ReportStatus.DRAFT,
        version=version,
    )


def record_report(session: Session, investigation_id: UUID, report: IncidentReport) -> Report:
    """Persist a report as the next version for its investigation."""
    repository = ReportRepository(session)
    version = repository.latest_version(investigation_id) + 1
    row = repository.add(to_report(investigation_id, report, version=version))

    _logger.info(
        "incident_report_recorded",
        investigation_id=str(investigation_id),
        version=version,
        findings=len(report.findings),
        caveats=len(report.caveats),
        complete=report.is_complete,
    )
    return row


def finalize_report(
    session: Session, investigation_id: UUID, *, version: int | None = None
) -> Report:
    """Promote a report to final on a human decision.

    Separated from writing on purpose: an agent produces drafts, and only a
    recorded human decision makes one final. Collapsing the two would let the
    pipeline mark its own work approved.
    """
    repository = ReportRepository(session)
    row = (
        repository.for_version(investigation_id, version)
        if version is not None
        else repository.current(investigation_id)
    )
    if row is None:
        raise ValueError(f"no report to finalize for investigation {investigation_id}")

    row.status = ReportStatus.FINAL
    session.flush()
    _logger.info(
        "incident_report_finalized",
        investigation_id=str(investigation_id),
        version=row.version,
    )
    return row

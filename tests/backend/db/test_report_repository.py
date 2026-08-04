"""Integration tests for persisting incident reports.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. The property under test is
that regeneration adds a version rather than replacing one — the document an
analyst actually read has to stay readable, because that is what their decision
rested on.
"""

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db.orm.investigation import Investigation
from backend.db.orm.reporting import Report
from backend.db.repositories.reporting import ReportRepository
from backend.services.report import finalize_report, record_report, to_report
from models.enums import ReportStatus, Severity, TriggerSource, Verdict
from models.report import IncidentReport, ReportSectionKind
from models.values import Citation


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    record = Investigation(trigger_source=TriggerSource.ALERT, title="report fixture")
    db_session.add(record)
    db_session.flush()
    return record


def _report(**overrides: object) -> IncidentReport:
    payload: dict[str, object] = {
        "investigation_id": "inv-1",
        "title": "Suspected credential attack on web-01",
        "executive_summary": "Assessed as malicious with high severity.",
        "technical_body": "# Suspected credential attack\n\n## Timeline\n",
        "verdict": Verdict.MALICIOUS,
        "severity": Severity.HIGH,
        "confidence": 0.82,
        "citations": [
            Citation(
                source_id="nvd",
                source="NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                title="CVE-2021-44228",
            )
        ],
        "generated_from": [ReportSectionKind.EVIDENCE, ReportSectionKind.THREAT],
    }
    payload.update(overrides)
    return IncidentReport(**payload)


def test_a_report_round_trips_with_both_documents(
    db_session: Session, investigation: Investigation
) -> None:
    row = record_report(db_session, investigation.id, _report())

    assert row.executive_summary.startswith("Assessed as malicious")
    assert row.technical_body.startswith("# Suspected credential attack")
    assert row.version == 1


def test_citations_travel_with_the_row(db_session: Session, investigation: Investigation) -> None:
    row = record_report(db_session, investigation.id, _report())
    assert row.citations[0]["url"].endswith("/CVE-2021-44228")


def test_a_report_is_written_as_a_draft(db_session: Session, investigation: Investigation) -> None:
    """An agent has no authority to declare its own output approved."""
    row = record_report(db_session, investigation.id, _report(status=ReportStatus.FINAL))
    assert row.status is ReportStatus.DRAFT


def test_regeneration_adds_a_version_rather_than_replacing_one(
    db_session: Session, investigation: Investigation
) -> None:
    first = record_report(db_session, investigation.id, _report())
    second = record_report(
        db_session, investigation.id, _report(executive_summary="Revised after new evidence.")
    )

    assert (first.version, second.version) == (1, 2)
    repository = ReportRepository(db_session)
    assert len(repository.history(investigation.id)) == 2


def test_the_document_a_decision_rested_on_stays_readable(
    db_session: Session, investigation: Investigation
) -> None:
    record_report(db_session, investigation.id, _report())
    record_report(db_session, investigation.id, _report(executive_summary="Revised."))

    repository = ReportRepository(db_session)
    original = repository.for_version(investigation.id, 1)
    assert original is not None
    assert original.executive_summary.startswith("Assessed as malicious")


def test_the_current_report_is_the_latest_version(
    db_session: Session, investigation: Investigation
) -> None:
    record_report(db_session, investigation.id, _report())
    record_report(db_session, investigation.id, _report(executive_summary="Revised."))

    current = ReportRepository(db_session).current(investigation.id)
    assert current is not None
    assert current.version == 2
    assert current.executive_summary == "Revised."


def test_two_reports_cannot_share_a_version(
    db_session: Session, investigation: Investigation
) -> None:
    """Enforced by the database, not by convention."""
    record_report(db_session, investigation.id, _report())
    db_session.add(to_report(investigation.id, _report(), version=1))

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_an_investigation_with_no_report_reports_nothing(
    db_session: Session, investigation: Investigation
) -> None:
    repository = ReportRepository(db_session)
    assert repository.current(investigation.id) is None
    assert repository.latest_version(investigation.id) == 0


def test_a_human_decision_promotes_a_draft_to_final(
    db_session: Session, investigation: Investigation
) -> None:
    record_report(db_session, investigation.id, _report())
    finalized = finalize_report(db_session, investigation.id)

    assert finalized.status is ReportStatus.FINAL
    assert finalized.version == 1


def test_an_earlier_version_can_be_finalized_explicitly(
    db_session: Session, investigation: Investigation
) -> None:
    record_report(db_session, investigation.id, _report())
    record_report(db_session, investigation.id, _report(executive_summary="Revised."))

    finalized = finalize_report(db_session, investigation.id, version=1)
    assert finalized.version == 1
    assert ReportRepository(db_session).current(investigation.id).status is ReportStatus.DRAFT  # type: ignore[union-attr]


def test_finalizing_a_report_that_does_not_exist_fails_loudly(
    db_session: Session, investigation: Investigation
) -> None:
    with pytest.raises(ValueError, match="no report to finalize"):
        finalize_report(db_session, investigation.id)


def test_versions_are_isolated_per_investigation(db_session: Session) -> None:
    first = Investigation(trigger_source=TriggerSource.ALERT, title="one")
    second = Investigation(trigger_source=TriggerSource.ALERT, title="two")
    db_session.add_all([first, second])
    db_session.flush()

    record_report(db_session, first.id, _report())
    record_report(db_session, first.id, _report())
    row = record_report(db_session, second.id, _report())

    assert row.version == 1


def test_mapping_is_pure_and_does_not_touch_the_session() -> None:
    from uuid import uuid4

    row: Report = to_report(uuid4(), _report(), version=7)
    assert row.version == 7
    assert row.status is ReportStatus.DRAFT

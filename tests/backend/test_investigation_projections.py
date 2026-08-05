"""Unit tests for the read projections the dashboard renders.

These exercise the service directly, without HTTP, because the properties under
test are about *what the projection says* rather than about routing: a stage with
no record must not read as complete, a skipped stage must be distinguishable from
a pending one, and an open gate must be reported even when there is nothing in
the plan to approve.
"""

from typing import Any

import pytest
from sqlalchemy.orm import Session

from backend.api.schemas.investigations import CreateInvestigationRequest
from backend.db.orm.investigation import Investigation
from backend.services import investigations as service
from backend.services.report import record_report_content
from graph.nodes import CVE_RESEARCH, LOG_ANALYSIS, THREAT_DETECTION
from models.enums import InvestigationStatus, Severity, TriggerSource


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    return service.create_investigation(
        db_session,
        request=CreateInvestigationRequest(title="projection fixture"),
        actor_id=None,
    )


# --- Creation ---------------------------------------------------------------


def test_a_new_investigation_opens_with_no_stage_history(investigation: Investigation) -> None:
    assert investigation.status is InvestigationStatus.OPEN
    assert investigation.pipeline == {}


def test_estate_context_is_pinned_at_creation(db_session: Session) -> None:
    """A replay is judged against the estate as it was, not as it later became."""
    row = service.create_investigation(
        db_session,
        request=CreateInvestigationRequest(
            trigger_source=TriggerSource.ALERT,
            critical_assets=["db-01"],
            internal_networks=["10.0.0.0/8"],
        ),
        actor_id=None,
    )
    assert row.config_snapshot == {
        "critical_assets": ["db-01"],
        "internal_networks": ["10.0.0.0/8"],
    }


def test_an_untitled_investigation_still_names_itself(db_session: Session) -> None:
    """A queue row with no title is one an analyst cannot triage from the list."""
    row = service.create_investigation(
        db_session,
        request=CreateInvestigationRequest(trigger_source=TriggerSource.SCHEDULED),
        actor_id=None,
    )
    assert row.title


# --- Stage recording --------------------------------------------------------


def test_a_stage_with_no_record_is_not_complete(
    db_session: Session, investigation: Investigation
) -> None:
    """Silence is not evidence that something succeeded."""
    stages = {stage.name: stage for stage in service.pipeline_of(investigation)}
    assert all(not stage.complete for stage in stages.values())
    assert all(not stage.skipped for stage in stages.values())


def test_recording_a_stage_survives_the_json_column(
    db_session: Session, investigation: Investigation
) -> None:
    """SQLAlchemy does not track in-place edits, so the mapping is re-assigned."""
    service.record_stage(db_session, investigation.id, LOG_ANALYSIS, detail="12 event(s)")
    db_session.expire_all()

    reloaded = db_session.get(Investigation, investigation.id)
    assert reloaded is not None
    assert reloaded.pipeline[LOG_ANALYSIS]["status"] == "complete"
    assert reloaded.pipeline[LOG_ANALYSIS]["detail"] == "12 event(s)"


def test_recording_a_second_stage_keeps_the_first(
    db_session: Session, investigation: Investigation
) -> None:
    service.record_stage(db_session, investigation.id, LOG_ANALYSIS)
    service.record_stage(db_session, investigation.id, THREAT_DETECTION)
    db_session.expire_all()

    reloaded = db_session.get(Investigation, investigation.id)
    assert reloaded is not None
    assert set(reloaded.pipeline) == {LOG_ANALYSIS, THREAT_DETECTION}


def test_a_skipped_stage_is_not_a_pending_one(
    db_session: Session, investigation: Investigation
) -> None:
    """Work correctly not done must not read as work still outstanding."""
    service.record_stage(
        db_session,
        investigation.id,
        CVE_RESEARCH,
        status=service.STAGE_SKIPPED,
        detail="benign verdict",
    )
    db_session.expire_all()
    reloaded = db_session.get(Investigation, investigation.id)
    assert reloaded is not None

    stage = next(s for s in service.pipeline_of(reloaded) if s.name == CVE_RESEARCH)
    assert stage.skipped is True
    assert stage.complete is False
    assert service.cve_research_ran(db_session, reloaded) is False


def test_a_failed_stage_is_neither_complete_nor_skipped(
    db_session: Session, investigation: Investigation
) -> None:
    service.record_stage(
        db_session,
        investigation.id,
        THREAT_DETECTION,
        status=service.STAGE_FAILED,
        detail="Timeout",
    )
    db_session.expire_all()
    reloaded = db_session.get(Investigation, investigation.id)
    assert reloaded is not None

    stage = next(s for s in service.pipeline_of(reloaded) if s.name == THREAT_DETECTION)
    assert stage.complete is False
    assert stage.skipped is False
    assert stage.detail == "Timeout"


def test_the_stage_order_is_the_pipeline_order(investigation: Investigation) -> None:
    assert [stage.name for stage in service.pipeline_of(investigation)] == [
        name for name, _ in service.STAGES
    ]


# --- Lifecycle --------------------------------------------------------------


def test_closing_stamps_the_closure_time(db_session: Session, investigation: Investigation) -> None:
    row = service.mark_status(db_session, investigation.id, InvestigationStatus.CLOSED)
    assert row is not None
    assert row.closed_at is not None


def test_a_non_terminal_status_does_not_stamp_closure(
    db_session: Session, investigation: Investigation
) -> None:
    row = service.mark_status(db_session, investigation.id, InvestigationStatus.IN_PROGRESS)
    assert row is not None
    assert row.closed_at is None


def test_the_headline_is_carried_onto_the_case_record(
    db_session: Session, investigation: Investigation
) -> None:
    """The queue must be sortable by how bad something is without opening it."""
    service.set_headline(
        db_session, investigation.id, severity=Severity.HIGH, summary="Credentials guessed."
    )
    db_session.expire_all()

    reloaded = db_session.get(Investigation, investigation.id)
    assert reloaded is not None
    assert reloaded.severity is Severity.HIGH
    assert reloaded.summary == "Credentials guessed."


# --- Snapshots and approvals ------------------------------------------------


def test_a_snapshot_of_a_fresh_case_reports_nothing_done(
    db_session: Session, investigation: Investigation
) -> None:
    snapshot = service.snapshot_of(db_session, investigation)

    assert snapshot.event_count == 0
    assert snapshot.recommendation_count == 0
    assert snapshot.report_version == 0
    assert snapshot.awaiting_human is False
    assert snapshot.verdict is None


def test_an_open_gate_is_reported_even_with_an_empty_plan(
    db_session: Session, investigation: Investigation
) -> None:
    """Otherwise a screen driven by the item count renders a stopped pipeline as idle."""
    service.mark_status(db_session, investigation.id, InvestigationStatus.AWAITING_APPROVAL)
    db_session.expire_all()
    reloaded = db_session.get(Investigation, investigation.id)
    assert reloaded is not None

    pending = service.pending_approvals_of(db_session, reloaded)
    assert pending.gate_open is True
    assert pending.items == []


def test_a_draft_report_is_itself_an_item_awaiting_a_person(
    db_session: Session, investigation: Investigation
) -> None:
    record_report_content(
        db_session,
        investigation.id,
        executive_summary="Assessed as suspicious.",
        technical_body="# Report",
        citations=[],
    )
    pending = service.pending_approvals_of(db_session, investigation)

    assert [item.kind for item in pending.items] == ["report"]
    assert pending.items[0].title == "Incident report v1"


def test_the_queue_counts_under_the_same_filter_it_lists(db_session: Session) -> None:
    for index in range(3):
        row = service.create_investigation(
            db_session,
            request=CreateInvestigationRequest(title=f"case {index}"),
            actor_id=None,
        )
        if index == 0:
            service.mark_status(db_session, row.id, InvestigationStatus.CLOSED)

    closed = service.list_investigations(
        db_session, limit=10, offset=0, status=InvestigationStatus.CLOSED
    )
    assert closed.total == 1
    assert len(closed.items) == 1


def test_paging_reports_its_own_bounds(db_session: Session) -> None:
    for index in range(5):
        service.create_investigation(
            db_session, request=CreateInvestigationRequest(title=f"case {index}"), actor_id=None
        )

    page = service.list_investigations(db_session, limit=2, offset=2)
    assert page.total == 5
    assert page.limit == 2
    assert page.offset == 2
    assert len(page.items) == 2


def test_a_soft_deleted_case_leaves_the_queue(db_session: Session) -> None:
    row = service.create_investigation(
        db_session, request=CreateInvestigationRequest(title="deleted"), actor_id=None
    )
    assert service.list_investigations(db_session, limit=10, offset=0).total == 1

    row.deleted_at = service._utcnow()
    db_session.flush()
    assert service.list_investigations(db_session, limit=10, offset=0).total == 0


# --- Contract bounds --------------------------------------------------------


def test_a_seed_cannot_be_unbounded() -> None:
    """One request must not be able to pin a worker for minutes."""
    from pydantic import ValidationError

    from backend.api.schemas.investigations import MAX_SEED_RECORDS

    oversized: list[dict[str, Any]] = [
        {
            "record_id": str(index),
            "source_id": "s",
            "source_kind": "file",
            "content": "x",
        }
        for index in range(MAX_SEED_RECORDS + 1)
    ]
    with pytest.raises(ValidationError):
        CreateInvestigationRequest(evidence={"raw_records": oversized})

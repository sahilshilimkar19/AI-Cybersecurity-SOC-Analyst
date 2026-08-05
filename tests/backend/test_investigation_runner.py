"""Tests for the background investigation runner.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. What is under test is the
runner's behavior when things go wrong, because the happy path is already
covered end-to-end through the API. Three properties matter:

* a run that dies leaves the work already done behind it, and says where it died;
* an unreadable record costs that record, not the whole timeline;
* nothing the runner does closes a case on its own.
"""

from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from backend.api.schemas.investigations import CreateInvestigationRequest
from backend.db.orm.investigation import Investigation
from backend.services import investigations as service
from backend.workers import investigations as runner
from graph.nodes import CLOSE, LOG_ANALYSIS, THREAT_DETECTION, TRIAGE
from models.enums import InvestigationStatus


class ExplodingGraph:
    """A graph whose run fails after reporting one completed node."""

    def __init__(self, *, report: tuple[str, dict[str, Any]] | None = None) -> None:
        self._report = report

    def start(self, **kwargs: Any) -> Any:
        on_node = kwargs.get("on_node")
        if self._report is not None and on_node is not None:
            on_node(*self._report)
        raise RuntimeError("the checkpointer went away")


def _as_graph(stub: ExplodingGraph) -> Any:
    """The runner only calls ``start``; the stub satisfies that much of the port."""
    return cast("Any", stub)


@pytest.fixture
def factory(db_engine: Engine) -> Any:
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def investigation_id(factory: Any) -> UUID:
    session = factory()
    try:
        row = service.create_investigation(
            session, request=CreateInvestigationRequest(title="runner fixture"), actor_id=None
        )
        session.commit()
        return UUID(str(row.id))
    finally:
        session.close()


def _reload(factory: Any, investigation_id: UUID) -> Investigation:
    session = factory()
    try:
        row: Investigation | None = session.get(Investigation, investigation_id)
        assert row is not None
        session.expunge(row)
        return row
    finally:
        session.close()


# --- Failure ----------------------------------------------------------------


def test_a_failed_run_records_where_it_stopped(factory: Any, investigation_id: UUID) -> None:
    runner.run_investigation(
        factory,
        _as_graph(ExplodingGraph()),
        investigation_id=investigation_id,
        request=CreateInvestigationRequest(),
    )

    row = _reload(factory, investigation_id)
    assert row.pipeline[LOG_ANALYSIS]["status"] == service.STAGE_FAILED
    assert row.pipeline[LOG_ANALYSIS]["detail"] == "RuntimeError"


def test_a_failed_run_keeps_the_work_already_done(factory: Any, investigation_id: UUID) -> None:
    """An investigation's worth of analysis is not discarded because a later stage died."""
    graph = _as_graph(
        ExplodingGraph(
            report=(LOG_ANALYSIS, {"investigation": {"normalized_events": []}}),
        )
    )
    runner.run_investigation(
        factory, graph, investigation_id=investigation_id, request=CreateInvestigationRequest()
    )

    row = _reload(factory, investigation_id)
    assert row.pipeline[LOG_ANALYSIS]["status"] == service.STAGE_COMPLETE
    assert row.pipeline[THREAT_DETECTION]["status"] == service.STAGE_FAILED


def test_a_failed_run_does_not_close_the_case(factory: Any, investigation_id: UUID) -> None:
    """A failure is not a disposition; only a person closes an investigation."""
    runner.run_investigation(
        factory,
        _as_graph(ExplodingGraph()),
        investigation_id=investigation_id,
        request=CreateInvestigationRequest(),
    )
    assert _reload(factory, investigation_id).status is InvestigationStatus.IN_PROGRESS


def test_the_failed_stage_is_the_first_one_with_no_outcome(
    factory: Any, investigation_id: UUID
) -> None:
    session = factory()
    try:
        service.record_stage(session, investigation_id, LOG_ANALYSIS)
        service.record_stage(
            session, investigation_id, "cve_research", status=service.STAGE_SKIPPED
        )
        session.commit()
        assert runner._failed_stage(session, investigation_id) == THREAT_DETECTION
    finally:
        session.close()


# --- Degradation ------------------------------------------------------------


def test_an_unreadable_record_costs_that_record_only() -> None:
    """One malformed event must not cost the whole timeline."""
    events, unreadable = runner._normalized_events(
        [
            {"not": "an event"},
            {"also": "not an event"},
        ]
    )
    assert events == []
    assert unreadable == 2


def test_readable_records_survive_alongside_unreadable_ones() -> None:
    good = {
        "event_id": "e1",
        "record_id": "r1",
        "source_id": "hostlogs",
        "source_kind": "file",
        "log_format": "syslog_rfc3164",
        "event_time": "2024-10-07T12:34:56Z",
    }
    events, unreadable = runner._normalized_events([good, {"bad": True}])

    assert len(events) == 1
    assert unreadable == 1


# --- Status transitions -----------------------------------------------------


def test_reaching_triage_asks_for_a_human(factory: Any, investigation_id: UUID) -> None:
    session = factory()
    try:
        runner._persist(session, investigation_id, TRIAGE, {})
        session.commit()
    finally:
        session.close()

    assert _reload(factory, investigation_id).status is InvestigationStatus.AWAITING_APPROVAL


def test_reaching_close_closes_the_case(factory: Any, investigation_id: UUID) -> None:
    session = factory()
    try:
        runner._persist(session, investigation_id, CLOSE, {})
        session.commit()
    finally:
        session.close()

    row = _reload(factory, investigation_id)
    assert row.status is InvestigationStatus.CLOSED
    assert row.closed_at is not None


def test_an_unknown_node_writes_nothing(factory: Any, investigation_id: UUID) -> None:
    """Only the nodes that produce artifacts are persisted; the rest are control flow."""
    session = factory()
    try:
        runner._persist(session, investigation_id, "ingest_seed", {})
        session.commit()
    finally:
        session.close()

    row = _reload(factory, investigation_id)
    assert row.pipeline == {}
    assert row.status is InvestigationStatus.OPEN


def test_a_write_for_a_missing_investigation_is_survivable(factory: Any) -> None:
    """Defensive: a stage report for a deleted case must not crash the run."""
    session = factory()
    try:
        service.record_stage(session, uuid4(), LOG_ANALYSIS)
        assert service.mark_status(session, uuid4(), InvestigationStatus.CLOSED) is None
        service.set_headline(session, uuid4(), summary="ignored")
    finally:
        session.close()

"""Integration tests for persisting normalized log evidence.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from backend.db.orm.investigation import Investigation
from backend.db.repositories.evidence import LogEventRepository
from backend.services.evidence import record_log_events, to_log_event
from models.enums import TriggerSource
from models.logs import (
    Entity,
    EntityType,
    EventType,
    LogFormat,
    LogSourceKind,
    NormalizedEvent,
)


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    record = Investigation(trigger_source=TriggerSource.ALERT, title="evidence fixture")
    db_session.add(record)
    db_session.flush()
    return record


def _event(event_id: str = "evt-1", *, minute: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        record_id=f"r-{event_id}",
        source_id="hostlogs",
        source_kind=LogSourceKind.FILE,
        log_format=LogFormat.SYSLOG_RFC3164,
        event_time=datetime(2024, 10, 7, 12, minute, tzinfo=UTC),
        event_type=EventType.AUTH_FAILURE,
        host="web-01",
        actor="admin",
        action="sshd",
        outcome="failure",
        message="Failed password for invalid user admin",
        entities=[Entity(type=EntityType.IP_ADDRESS, value="203.0.113.9")],
        raw_ref="auth.log#L1",
        notability=0.72,
        confidence=0.9,
    )


def test_mapping_carries_full_provenance() -> None:
    row = to_log_event(investigation_id=__import__("uuid").uuid4(), event=_event())

    assert row.source == "hostlogs"
    assert row.event_type == EventType.AUTH_FAILURE.value
    assert row.raw_ref == "auth.log#L1"
    assert row.notability == 0.72
    provenance = row.provenance
    assert provenance["record_id"] == "r-evt-1"
    assert provenance["log_format"] == LogFormat.SYSLOG_RFC3164.value
    assert provenance["host"] == "web-01"
    assert provenance["confidence"] == 0.9
    assert provenance["entities"] == [{"type": "ip", "value": "203.0.113.9"}]


def test_events_round_trip_through_the_database(
    db_session: Session, investigation: Investigation
) -> None:
    written = record_log_events(
        db_session, investigation.id, [_event("evt-1", minute=1), _event("evt-2", minute=2)]
    )
    assert written == 2

    stored = LogEventRepository(db_session).for_investigation(investigation.id)
    assert [row.provenance["event_id"] for row in stored] == ["evt-1", "evt-2"]
    assert stored[0].actor == "admin"
    assert stored[0].raw_ref == "auth.log#L1"


def test_events_are_returned_in_chronological_order(
    db_session: Session, investigation: Investigation
) -> None:
    record_log_events(
        db_session, investigation.id, [_event("late", minute=30), _event("early", minute=5)]
    )

    stored = LogEventRepository(db_session).for_investigation(investigation.id)
    assert [row.provenance["event_id"] for row in stored] == ["early", "late"]


def test_persisting_nothing_writes_nothing(
    db_session: Session, investigation: Investigation
) -> None:
    assert record_log_events(db_session, investigation.id, []) == 0
    assert LogEventRepository(db_session).count_for_investigation(investigation.id) == 0


def test_events_are_scoped_to_their_investigation(
    db_session: Session, investigation: Investigation
) -> None:
    other = Investigation(trigger_source=TriggerSource.ANALYST)
    db_session.add(other)
    db_session.flush()

    record_log_events(db_session, investigation.id, [_event("mine")])

    repository = LogEventRepository(db_session)
    assert repository.count_for_investigation(investigation.id) == 1
    assert repository.count_for_investigation(other.id) == 0

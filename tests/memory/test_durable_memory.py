"""Integration tests for the PostgreSQL-backed memory tiers.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.db.orm.analysis import ThreatAssessment
from backend.db.orm.conversation import Conversation, Message
from backend.db.orm.investigation import Investigation
from backend.db.repositories.memory import SessionMemoryRepository
from config.settings import Settings
from memory.conversation import SqlConversationMemory
from memory.durable import SqlDurableMemoryStore
from memory.history import SqlInvestigationHistory
from memory.hot import InMemoryHotStore
from memory.long_term import SqlLongTermMemory
from memory.service import build_memory_service
from memory.session import SessionMemory
from models.enums import (
    InvestigationStatus,
    MemoryIndexKind,
    MessageAuthorType,
    Severity,
    TriagePriority,
    TriggerSource,
    Verdict,
)
from tests.memory.conftest import SessionScope


def test_durable_store_appends_revisions(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    store = SqlDurableMemoryStore(session_scope)

    first = store.append(
        investigation_id=investigation.id, key="verdict", value={"v": "suspicious"}, source="pass1"
    )
    second = store.append(
        investigation_id=investigation.id, key="verdict", value={"v": "malicious"}, source="pass2"
    )

    assert first.revision == 1
    assert second.revision == 2

    latest = store.latest(investigation.id, "verdict")
    assert latest is not None
    assert latest.value == {"v": "malicious"}
    assert latest.source == "pass2"


def test_durable_history_preserves_provenance(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    store = SqlDurableMemoryStore(session_scope)
    store.append(investigation_id=investigation.id, key="k", value={"n": 1}, source="log")
    store.append(investigation_id=investigation.id, key="k", value={"n": 2}, source="threat")

    history = store.history(investigation.id, "k")

    assert [entry.revision for entry in history] == [1, 2]
    assert [entry.source for entry in history] == ["log", "threat"]
    assert history[0].value == {"n": 1}


def test_durable_latest_all_returns_one_row_per_key(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    store = SqlDurableMemoryStore(session_scope)
    store.append(investigation_id=investigation.id, key="a", value={"n": 1}, source="s")
    store.append(investigation_id=investigation.id, key="a", value={"n": 2}, source="s")
    store.append(investigation_id=investigation.id, key="b", value={"n": 3}, source="s")

    entries = store.latest_all(investigation.id)

    assert [entry.key for entry in entries] == ["a", "b"]
    assert [entry.value for entry in entries] == [{"n": 2}, {"n": 3}]


def test_durable_latest_missing_returns_none(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    store = SqlDurableMemoryStore(session_scope)
    assert store.latest(investigation.id, "absent") is None


def test_session_memory_survives_restart_against_postgres(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    """A fresh worker with a cold cache recovers the investigation from Postgres."""
    durable = SqlDurableMemoryStore(session_scope)
    before = SessionMemory(hot=InMemoryHotStore(), durable=durable)
    before.write(investigation.id, "timeline", {"events": 3}, source="log_analyzer")
    before.write(investigation.id, "verdict", {"v": "malicious"}, source="threat_detector")

    after = SessionMemory(hot=InMemoryHotStore(), durable=durable)
    entries = after.read_all(investigation.id)

    assert {entry.key for entry in entries} == {"timeline", "verdict"}
    assert after.stats.recoveries == 1


def test_history_index_is_idempotent(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    history = SqlInvestigationHistory(session_scope)

    history.index_investigation(investigation.id, {MemoryIndexKind.CVE: ["CVE-2021-44228"]})
    history.index_investigation(investigation.id, {MemoryIndexKind.CVE: ["CVE-2021-44228"]})

    related = history.find_related(MemoryIndexKind.CVE, "CVE-2021-44228")
    assert [item.investigation_id for item in related] == [investigation.id]


def test_history_recalls_prior_investigations_by_each_dimension(
    session_scope: SessionScope, investigation: Investigation
) -> None:
    history = SqlInvestigationHistory(session_scope)
    written = history.index_investigation(
        investigation.id,
        {
            MemoryIndexKind.ASSET: ["web-01"],
            MemoryIndexKind.IOC: ["1.2.3.4"],
            MemoryIndexKind.TECHNIQUE: ["T1059"],
        },
    )

    assert written == 3
    assert history.find_related(MemoryIndexKind.ASSET, "web-01")
    assert history.find_related(MemoryIndexKind.IOC, "1.2.3.4")
    assert history.find_related(MemoryIndexKind.TECHNIQUE, "T1059")
    assert history.find_related(MemoryIndexKind.CVE, "CVE-0000-0000") == []


def test_long_term_memory_reads_outcome_with_verdict(
    session_scope: SessionScope, db_session: Session, investigation: Investigation
) -> None:
    investigation.status = InvestigationStatus.CLOSED
    investigation.severity = Severity.HIGH
    db_session.add(
        ThreatAssessment(
            investigation_id=investigation.id,
            verdict=Verdict.MALICIOUS,
            severity=Severity.HIGH,
            triage_priority=TriagePriority.URGENT,
            confidence=0.9,
            version=1,
        )
    )
    db_session.flush()

    outcome = SqlLongTermMemory(session_scope).outcome_for(investigation.id)

    assert outcome is not None
    assert outcome.status == InvestigationStatus.CLOSED.value
    assert outcome.severity == Severity.HIGH.value
    assert outcome.verdict == Verdict.MALICIOUS.value


def test_long_term_memory_unknown_investigation_returns_none(
    session_scope: SessionScope,
) -> None:
    assert SqlLongTermMemory(session_scope).outcome_for(uuid4()) is None


def test_long_term_memory_lists_closed_investigations(
    session_scope: SessionScope, db_session: Session, investigation: Investigation
) -> None:
    investigation.status = InvestigationStatus.CLOSED
    open_case = Investigation(trigger_source=TriggerSource.ALERT)
    db_session.add(open_case)
    db_session.flush()

    outcomes = SqlLongTermMemory(session_scope).recent_outcomes()

    ids = [outcome.investigation_id for outcome in outcomes]
    assert investigation.id in ids
    assert open_case.id not in ids


def test_conversation_memory_returns_turns_oldest_first(
    session_scope: SessionScope, db_session: Session, investigation: Investigation
) -> None:
    conversation = Conversation(investigation_id=investigation.id)
    db_session.add(conversation)
    db_session.flush()
    # Explicit timestamps: within one transaction Postgres' now() is constant, so
    # relying on the server default would leave the turns tied rather than ordered.
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for offset, text_value in enumerate(["first", "second", "third"]):
        db_session.add(
            Message(
                conversation_id=conversation.id,
                author_type=MessageAuthorType.HUMAN,
                content=text_value,
                created_at=base + timedelta(minutes=offset),
            )
        )
    db_session.flush()

    turns = SqlConversationMemory(session_scope).recent_turns(investigation.id, limit=2)

    # The two most recent turns, returned in chronological order.
    assert [turn.content for turn in turns] == ["second", "third"]


def test_conversation_memory_for_unknown_investigation_is_empty(
    session_scope: SessionScope,
) -> None:
    assert SqlConversationMemory(session_scope).recent_turns(uuid4()) == []


def test_factory_wires_the_sql_backed_tiers(
    session_scope: SessionScope, db_session: Session, investigation: Investigation
) -> None:
    """With a session scope the service persists through PostgreSQL end to end."""
    service = build_memory_service(Settings(), session_scope=session_scope)

    service.remember(investigation.id, "verdict", {"v": "malicious"}, source="threat_detector")
    service.history.index_investigation(investigation.id, {MemoryIndexKind.ASSET: ["web-01"]})

    # The write really landed in the database, not just an in-process store.
    persisted = SessionMemoryRepository(db_session).latest(investigation.id, "verdict")
    assert persisted is not None
    assert persisted.value == {"v": "malicious"}
    assert persisted.source == "threat_detector"

    bundle = service.materialize_context(investigation.id)
    assert [item.key for item in bundle.session] == ["verdict"]

    related = service.history.find_related(MemoryIndexKind.ASSET, "web-01")
    assert [item.investigation_id for item in related] == [investigation.id]

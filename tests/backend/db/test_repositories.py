"""Database integration tests for repositories (requires PostgreSQL)."""

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.orm import AuditLog, Investigation
from backend.db.repositories import AuditLogRepository, Repository
from models.enums import InvestigationStatus, TriggerSource


def test_repository_add_get_list(db_session: Session) -> None:
    repo = Repository(db_session, Investigation)

    saved = repo.add(Investigation(trigger_source=TriggerSource.ANALYST))

    assert saved.id is not None
    assert saved.created_at is not None
    assert saved.status is InvestigationStatus.OPEN  # column default applied

    fetched = repo.get(saved.id)
    assert fetched is not None
    assert fetched.trigger_source is TriggerSource.ANALYST

    assert len(list(repo.list())) >= 1


def test_get_unknown_id_returns_none(db_session: Session) -> None:
    repo = Repository(db_session, Investigation)

    assert repo.get(uuid4()) is None


def test_audit_append_is_signed_and_persisted(db_session: Session) -> None:
    repo = AuditLogRepository(db_session)

    entry = repo.append(
        action="investigation.created",
        entity_type="investigation",
        entity_id=uuid4(),
        actor_id=uuid4(),
    )

    assert len(entry.signature) == 64

    rows = db_session.execute(select(AuditLog)).scalars().all()
    assert any(row.id == entry.id for row in rows)


def test_enum_round_trips_through_database(db_session: Session) -> None:
    repo = Repository(db_session, Investigation)

    saved = repo.add(Investigation(trigger_source=TriggerSource.SCHEDULED))
    db_session.expire(saved)

    reloaded = repo.get(saved.id)
    assert reloaded is not None
    assert reloaded.trigger_source is TriggerSource.SCHEDULED

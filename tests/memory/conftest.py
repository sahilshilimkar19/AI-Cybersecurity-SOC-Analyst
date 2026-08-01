"""Fixtures for the memory suite's database integration tests."""

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager

import pytest
from sqlalchemy.orm import Session

from backend.db.orm.investigation import Investigation
from models.enums import TriggerSource

SessionScope = Callable[[], AbstractContextManager[Session]]


@pytest.fixture
def session_scope(db_session: Session) -> SessionScope:
    """A scope that reuses the test's transaction so everything rolls back.

    Writes are flushed rather than committed, so they are visible to subsequent
    reads in the same test but never escape it.
    """

    @contextmanager
    def scope() -> Iterator[Session]:
        yield db_session
        db_session.flush()

    return scope


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    """A persisted investigation to satisfy the memory tables' foreign keys."""
    record = Investigation(trigger_source=TriggerSource.ANALYST, title="memory fixture")
    db_session.add(record)
    db_session.flush()
    return record

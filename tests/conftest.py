"""Shared pytest fixtures.

The autouse fixture isolates every test from a developer's local ``.env`` file
and from any ``SOC_*`` application variables in the host environment, so tests
are deterministic. The separate ``SOC_TEST_DATABASE_URL`` (used only by database
integration tests) is intentionally preserved.

The database fixtures live here rather than in a suite-level conftest because
both the backend and memory suites need them.
"""

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

import backend.db  # noqa: F401 - registers all ORM tables on Base.metadata
from backend.db.base import Base
from config.settings import Settings, get_settings

_PRESERVED = {"SOC_TEST_DATABASE_URL", "SOC_TEST_REDIS_URL"}


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neutralize any local ``.env`` and ``SOC_*`` vars; clear the settings cache."""
    # Disable reading a developer-local .env so defaults are deterministic.
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    # Remove any SOC_* application variables inherited from the host environment.
    for name in list(os.environ):
        if name.startswith("SOC_") and name not in _PRESERVED:
            monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    """Session-scoped engine against the test database; skips if unavailable."""
    url = os.environ.get("SOC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("SOC_TEST_DATABASE_URL not set; skipping database integration tests")

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - environment dependent
        engine.dispose()
        pytest.skip(f"test database not reachable: {exc}")

    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Function-scoped session wrapped in a transaction that is rolled back."""
    connection = db_engine.connect()
    transaction = connection.begin()
    factory = sessionmaker(bind=connection, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()

"""Database engine and session management.

Provides pure factories (``create_db_engine`` / ``create_session_factory``) used
by tests and migrations, plus a lazily-initialized process-wide default used by
the application via ``session_scope``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from config.settings import Settings, get_settings


def create_db_engine(settings: Settings) -> Engine:
    """Create a new SQLAlchemy engine from settings."""
    return create_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        pool_pre_ping=True,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False)


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Return the process-wide default engine, creating it on first use."""
    global _engine, _session_factory
    if _engine is None:
        _engine = create_db_engine(get_settings())
        _session_factory = create_session_factory(_engine)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide default session factory."""
    global _session_factory
    if _session_factory is None:
        get_engine()
    if _session_factory is None:  # pragma: no cover - defensive, set by get_engine
        raise RuntimeError("session factory failed to initialize")
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session scope: commit on success, roll back on error."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

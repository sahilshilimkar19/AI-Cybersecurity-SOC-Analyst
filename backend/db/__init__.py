"""Database layer — ORM models, session management, repositories, object storage.

This package is part of ``backend/`` because the backend is the sole write
boundary to the system of record (governing invariant #7). Importing it
registers every ORM table on ``Base.metadata``.
"""

from backend.db import orm  # noqa: F401 - registers ORM tables on Base.metadata
from backend.db.base import Base
from backend.db.object_store import (
    InMemoryObjectStore,
    MinioObjectStore,
    ObjectStore,
    minio_object_store_from_settings,
)
from backend.db.repositories import AuditLogRepository, Repository
from backend.db.session import (
    create_db_engine,
    create_session_factory,
    get_engine,
    get_session_factory,
    session_scope,
)

__all__ = [
    "AuditLogRepository",
    "Base",
    "InMemoryObjectStore",
    "MinioObjectStore",
    "ObjectStore",
    "Repository",
    "create_db_engine",
    "create_session_factory",
    "get_engine",
    "get_session_factory",
    "minio_object_store_from_settings",
    "session_scope",
]

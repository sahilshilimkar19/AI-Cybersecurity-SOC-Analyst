"""Generic repository for ORM entities."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.base import Base

ModelT = TypeVar("ModelT", bound=Base)


class Repository(Generic[ModelT]):
    """Minimal create/read data-access for a single ORM model.

    Concrete repositories subclass this to add entity-specific queries. Writes
    are flushed (not committed) so the caller controls the transaction boundary.
    """

    def __init__(self, session: Session, model: type[ModelT]) -> None:
        self._session = session
        self._model = model

    def add(self, instance: ModelT) -> ModelT:
        """Stage a new instance and flush to assign server-side defaults."""
        self._session.add(instance)
        self._session.flush()
        return instance

    def get(self, entity_id: UUID) -> ModelT | None:
        """Return an entity by primary key, or ``None``."""
        return self._session.get(self._model, entity_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[ModelT]:
        """Return a page of entities."""
        stmt = select(self._model).limit(limit).offset(offset)
        return self._session.execute(stmt).scalars().all()

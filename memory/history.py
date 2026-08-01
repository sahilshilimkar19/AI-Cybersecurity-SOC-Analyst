"""Investigation history — the cross-investigation recall index (EDS §7).

Populated when an investigation closes and keyed by the dimensions analysts
actually pivot on: **asset, IoC, ATT&CK technique, CVE**. It answers "have we seen
this before?" without scanning the system of record, and later gives the Threat
Detector and Reporter their related-incident context.

Indexing is idempotent, so re-closing or re-indexing an investigation is safe.
A semantic (vector) index over this same data arrives with the RAG sprint; the
lookup contract here does not change when it does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from config.logging import get_logger
from models.enums import MemoryIndexKind
from models.memory import RelatedInvestigation

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session

_logger = get_logger(__name__)


class InvestigationHistoryMemory(Protocol):
    """Recall over previously closed investigations."""

    def index_investigation(
        self, investigation_id: UUID, values: Mapping[MemoryIndexKind, Sequence[str]]
    ) -> int: ...
    def find_related(
        self, kind: MemoryIndexKind, value: str, *, limit: int = 20
    ) -> list[RelatedInvestigation]: ...


class InMemoryInvestigationHistory:
    """In-process history index for tests and local development."""

    def __init__(self) -> None:
        self._index: dict[tuple[MemoryIndexKind, str], list[UUID]] = {}

    def index_investigation(
        self, investigation_id: UUID, values: Mapping[MemoryIndexKind, Sequence[str]]
    ) -> int:
        written = 0
        for kind, items in values.items():
            for item in items:
                bucket = self._index.setdefault((kind, item), [])
                if investigation_id not in bucket:
                    bucket.append(investigation_id)
                written += 1
        return written

    def find_related(
        self, kind: MemoryIndexKind, value: str, *, limit: int = 20
    ) -> list[RelatedInvestigation]:
        return [
            RelatedInvestigation(investigation_id=item, kind=kind, value=value)
            for item in self._index.get((kind, value), [])[:limit]
        ]


class SqlInvestigationHistory:
    """PostgreSQL-backed recall index."""

    def __init__(self, session_scope: Callable[[], AbstractContextManager[Session]]) -> None:
        self._session_scope = session_scope

    def index_investigation(
        self, investigation_id: UUID, values: Mapping[MemoryIndexKind, Sequence[str]]
    ) -> int:
        """Index a closed investigation under each recall dimension (idempotent)."""
        from backend.db.repositories.memory import InvestigationMemoryIndexRepository

        written = 0
        with self._session_scope() as session:
            repository = InvestigationMemoryIndexRepository(session)
            for kind, items in values.items():
                for item in items:
                    repository.index(investigation_id=investigation_id, kind=kind, value=item)
                    written += 1
        _logger.info(
            "investigation_indexed",
            investigation_id=str(investigation_id),
            entries=written,
        )
        return written

    def find_related(
        self, kind: MemoryIndexKind, value: str, *, limit: int = 20
    ) -> list[RelatedInvestigation]:
        """Return investigations previously indexed under this value."""
        from backend.db.repositories.memory import InvestigationMemoryIndexRepository

        with self._session_scope() as session:
            found = InvestigationMemoryIndexRepository(session).find_investigations(
                kind=kind, value=value, limit=limit
            )
        return [
            RelatedInvestigation(investigation_id=item, kind=kind, value=value) for item in found
        ]

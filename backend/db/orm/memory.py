"""ORM models backing the durable memory tiers (EDS §7).

Two tables serve the memory layer's durability requirements:

* ``session_memory_entries`` — the **durable** half of two-tier session memory.
  Writes are append-only revisions rather than in-place updates, so provenance is
  preserved and the hot (Redis) tier can always be rebuilt from here.
* ``investigation_memory_index`` — the recall index over **closed** investigations,
  keyed by asset / IoC / technique / CVE, so later agents can answer "have we seen
  this before?" without scanning the whole system of record.

The other tiers need no new tables: conversation and long-term memory read the
existing investigation entities, and knowledge memory is owned by the RAG
ingestion pipeline.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, str_enum_column
from models.enums import MemoryIndexKind


class SessionMemoryEntry(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One durable revision of a session-memory key. Append-only."""

    __tablename__ = "session_memory_entries"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "key",
            "revision",
            name="uq_session_memory_entries_investigation_key_revision",
        ),
        Index("ix_session_memory_entries_investigation_key", "investigation_id", "key"),
    )

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    key: Mapped[str] = mapped_column(String(255))
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    # Which node/agent wrote this revision — provenance is never dropped.
    source: Mapped[str] = mapped_column(String(255))
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class InvestigationMemoryIndexEntry(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A recall pointer from an indexed value (asset/IoC/technique/CVE) to an investigation."""

    __tablename__ = "investigation_memory_index"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "kind",
            "value",
            name="uq_investigation_memory_index_investigation_kind_value",
        ),
        Index("ix_investigation_memory_index_kind_value", "kind", "value"),
    )

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)
    kind: Mapped[MemoryIndexKind] = mapped_column(
        str_enum_column(MemoryIndexKind, "memory_index_kind")
    )
    value: Mapped[str] = mapped_column(String(512))

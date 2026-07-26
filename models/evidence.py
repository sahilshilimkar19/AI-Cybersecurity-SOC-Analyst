"""Log event (evidence) domain contract."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from models.base import IdentifiedModel


class LogEvent(IdentifiedModel):
    """A normalized, provenance-tagged security event.

    Evidence is immutable once written; the large raw record lives in object
    storage and is referenced by ``raw_ref`` (EDS §6).
    """

    investigation_id: UUID
    asset_id: UUID | None = None
    source: str
    event_time: datetime
    actor: str | None = None
    event_type: str
    raw_ref: str | None = None
    notability: float = Field(default=0.0, ge=0.0, le=1.0)
    provenance: dict[str, object] = Field(default_factory=dict)

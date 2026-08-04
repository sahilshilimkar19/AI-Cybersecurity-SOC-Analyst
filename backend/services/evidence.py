"""Persisting normalized log evidence (invariant #7).

The Log Analyzer *produces* evidence; the backend *writes* it. Keeping the write
here rather than inside the agent or the graph node preserves the sole-write-
boundary invariant and keeps agents free of database concerns.

Provenance travels with every row: the source, the original record id, the raw
reference, the parser that read it, and the confidence it was read with. An event
whose origin cannot be reconstructed is not evidence, so nothing is stored
without it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from backend.db.orm.evidence import LogEvent
from backend.db.repositories.evidence import LogEventRepository
from config.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.orm import Session

    from models.logs import NormalizedEvent

_logger = get_logger(__name__)


def to_log_event(investigation_id: UUID, event: NormalizedEvent) -> LogEvent:
    """Map a normalized event onto its persistent row, carrying provenance."""
    return LogEvent(
        investigation_id=investigation_id,
        source=event.source_id,
        event_time=event.event_time,
        actor=event.actor,
        event_type=event.event_type.value,
        raw_ref=event.raw_ref,
        notability=event.notability,
        provenance={
            "event_id": event.event_id,
            "record_id": event.record_id,
            "source_kind": event.source_kind.value,
            "log_format": event.log_format.value,
            "host": event.host,
            "action": event.action,
            "outcome": event.outcome,
            "confidence": event.confidence,
            "entities": [
                {"type": entity.type.value, "value": entity.value} for entity in event.entities
            ],
        },
    )


def record_log_events(
    session: Session, investigation_id: UUID, events: Sequence[NormalizedEvent]
) -> int:
    """Persist normalized events for an investigation, returning the count written."""
    if not events:
        return 0

    rows = [to_log_event(investigation_id, event) for event in events]
    written = LogEventRepository(session).add_many(rows)
    _logger.info("log_events_recorded", investigation_id=str(investigation_id), events=written)
    return written

"""Time-window correlation and notability scoring (EDS §4.2 required tools).

Correlation is what turns a pile of records into a story: events from different
sources that share a host, an account, an address, or a process, and that happen
close together in time, are probably describing the same activity.

Both functions here are deterministic and rule-based. Notability answers "how
much should a human look at this?" — deliberately *not* "is this malicious?",
which is the Threat Detector's job.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import TYPE_CHECKING

from models.logs import Correlation, CorrelationKind, EntityType, EventType

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.logs import NormalizedEvent

# Base notability per event type. Authentication failures and privilege changes
# lead because they are the events analysts most often need to see first; this
# is a triage prior, not a verdict, and is calibrated by fixtures.
_TYPE_NOTABILITY: dict[EventType, float] = {
    EventType.AUTH_FAILURE: 0.6,
    EventType.PRIVILEGE_CHANGE: 0.7,
    EventType.ACCOUNT_CHANGE: 0.6,
    EventType.PROCESS_START: 0.5,
    EventType.SERVICE_CONTROL: 0.5,
    EventType.NETWORK_CONNECTION: 0.4,
    EventType.CONFIGURATION_CHANGE: 0.4,
    EventType.FILE_ACCESS: 0.3,
    EventType.AUTH_SUCCESS: 0.2,
    EventType.OTHER: 0.1,
}

# Entities that make an event more useful to a human, because they give
# something to pivot on.
_ENTITY_BONUS: dict[EntityType, float] = {
    EntityType.FILE_HASH: 0.15,
    EntityType.IP_ADDRESS: 0.1,
    EntityType.URL: 0.1,
    EntityType.DOMAIN: 0.05,
    EntityType.PROCESS: 0.05,
}

# Which entity kinds drive which correlation, in reporting order.
_CORRELATION_ENTITIES: tuple[tuple[CorrelationKind, EntityType], ...] = (
    (CorrelationKind.SHARED_ADDRESS, EntityType.IP_ADDRESS),
    (CorrelationKind.SHARED_PROCESS, EntityType.PROCESS),
)


def score_notability(event: NormalizedEvent) -> float:
    """Score how much an event merits human attention, in ``0..1``.

    Combines the event-type prior with a bonus for pivotable entities and a
    penalty for a failed outcome being unknown; scaled by parse confidence so
    a shakily-parsed event never outranks a cleanly-parsed one.
    """
    score = _TYPE_NOTABILITY.get(event.event_type, 0.1)

    seen: set[EntityType] = set()
    for entity in event.entities:
        if entity.type in seen:
            continue
        seen.add(entity.type)
        score += _ENTITY_BONUS.get(entity.type, 0.0)

    if event.outcome == "failure":
        score += 0.1

    return round(min(1.0, max(0.0, score)) * event.confidence, 4)


def correlate_events(
    events: Sequence[NormalizedEvent], *, window: timedelta, minimum_events: int = 2
) -> list[Correlation]:
    """Group events that share an identifier within ``window`` of each other.

    Groups are built per key and then split wherever a gap larger than the
    window appears, so a host active on Monday and again on Friday yields two
    episodes rather than one implausible five-day cluster.
    """
    buckets: dict[tuple[CorrelationKind, str], list[NormalizedEvent]] = defaultdict(list)

    for event in events:
        if event.host:
            buckets[(CorrelationKind.SHARED_HOST, event.host.lower())].append(event)
        if event.actor:
            buckets[(CorrelationKind.SHARED_ACTOR, event.actor.lower())].append(event)
        for kind, entity_type in _CORRELATION_ENTITIES:
            for entity in event.entities:
                if entity.type is entity_type:
                    buckets[(kind, entity.value.lower())].append(event)

    correlations: list[Correlation] = []
    for (kind, key), bucket in sorted(
        buckets.items(), key=lambda item: (item[0][0].value, item[0][1])
    ):
        ordered = sorted(bucket, key=lambda event: (event.event_time, event.event_id))
        for episode in _split_by_gap(ordered, window):
            unique_ids = _unique_event_ids(episode)
            if len(unique_ids) < minimum_events:
                continue
            correlations.append(
                Correlation(
                    correlation_id=f"{kind.value}:{key}:{episode[0].event_time.isoformat()}",
                    kind=kind,
                    key=key,
                    event_ids=unique_ids,
                    window_start=episode[0].event_time,
                    window_end=episode[-1].event_time,
                    rationale=(
                        f"{len(unique_ids)} events share {kind.value.replace('shared_', '')} "
                        f"{key!r} within {_humanize(window)}"
                    ),
                )
            )
    return correlations


def _split_by_gap(
    events: Sequence[NormalizedEvent], window: timedelta
) -> list[list[NormalizedEvent]]:
    """Split time-ordered events wherever consecutive events are further apart than ``window``."""
    episodes: list[list[NormalizedEvent]] = []
    current: list[NormalizedEvent] = []
    for event in events:
        if current and event.event_time - current[-1].event_time > window:
            episodes.append(current)
            current = []
        current.append(event)
    if current:
        episodes.append(current)
    return episodes


def _unique_event_ids(events: Sequence[NormalizedEvent]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for event in events:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        ordered.append(event.event_id)
    return ordered


def _humanize(window: timedelta) -> str:
    seconds = int(window.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    return f"{hours}h" if hours < 24 else f"{hours // 24}d"

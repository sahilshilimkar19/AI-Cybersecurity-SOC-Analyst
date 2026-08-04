"""Tests for entity extraction, correlation, and notability scoring."""

from datetime import UTC, datetime, timedelta

import pytest

from models.logs import (
    CorrelationKind,
    Entity,
    EntityType,
    EventType,
    LogFormat,
    LogSourceKind,
    NormalizedEvent,
)
from tools.correlation import correlate_events, score_notability
from tools.extraction import extract_entities

BASE = datetime(2024, 10, 7, 12, 0, tzinfo=UTC)


def _event(
    event_id: str,
    *,
    minutes: int = 0,
    host: str | None = None,
    actor: str | None = None,
    entities: list[Entity] | None = None,
    event_type: EventType = EventType.OTHER,
    outcome: str | None = None,
    confidence: float = 1.0,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        record_id=event_id,
        source_id="hostlogs",
        source_kind=LogSourceKind.FILE,
        log_format=LogFormat.JSON,
        event_time=BASE + timedelta(minutes=minutes),
        event_type=event_type,
        host=host,
        actor=actor,
        outcome=outcome,
        entities=entities or [],
        confidence=confidence,
    )


# --- Extraction ------------------------------------------------------------


def test_extracts_addresses_domains_urls_and_hashes() -> None:
    text = (
        "connection from 203.0.113.9 to https://evil.example.com/payload "
        "hash 5d41402abc4b2a76b9719d911017c592 dropped C:\\Windows\\Temp\\bad.exe"
    )
    found = {(entity.type, entity.value) for entity in extract_entities(text)}

    assert (EntityType.IP_ADDRESS, "203.0.113.9") in found
    assert (EntityType.URL, "https://evil.example.com/payload") in found
    assert (EntityType.FILE_HASH, "5d41402abc4b2a76b9719d911017c592") in found
    assert (EntityType.PROCESS, "bad.exe") in found


def test_a_urls_host_is_not_also_reported_as_a_bare_domain() -> None:
    entities = extract_entities("see https://evil.example.com/x for details")
    domains = [entity.value for entity in entities if entity.type is EntityType.DOMAIN]
    assert domains == []


def test_unix_paths_are_extracted() -> None:
    entities = extract_entities("opened /etc/shadow for reading")
    assert any(
        entity.type is EntityType.FILE_PATH and entity.value == "/etc/shadow" for entity in entities
    )


def test_extra_structured_values_are_included() -> None:
    entities = extract_entities(
        "no identifiers here",
        extra=((EntityType.HOST, "web-01"), (EntityType.USER, "deploy")),
    )
    assert (EntityType.HOST, "web-01") in {(e.type, e.value) for e in entities}
    assert (EntityType.USER, "deploy") in {(e.type, e.value) for e in entities}


def test_empty_extras_are_skipped() -> None:
    assert extract_entities("nothing", extra=((EntityType.HOST, None),)) == []


def test_extraction_deduplicates_and_is_deterministic() -> None:
    text = "203.0.113.9 talked to 203.0.113.9 again"
    first = extract_entities(text)
    assert len(first) == 1
    assert [(e.type, e.value) for e in first] == [(e.type, e.value) for e in extract_entities(text)]


def test_invalid_addresses_are_not_extracted() -> None:
    entities = extract_entities("version 999.999.999.999 of the tool")
    assert not [e for e in entities if e.type is EntityType.IP_ADDRESS]


def test_extraction_does_not_judge_reputation() -> None:
    """Finding an indicator says nothing about whether it is hostile."""
    entities = extract_entities("connection to 203.0.113.9")
    assert all(not hasattr(entity, "reputation") for entity in entities)


# --- Notability ------------------------------------------------------------


def test_auth_failure_is_more_notable_than_auth_success() -> None:
    failure = _event("a", event_type=EventType.AUTH_FAILURE, outcome="failure")
    success = _event("b", event_type=EventType.AUTH_SUCCESS)
    assert score_notability(failure) > score_notability(success)


def test_pivotable_entities_raise_notability() -> None:
    plain = _event("a", event_type=EventType.PROCESS_START)
    with_hash = _event(
        "b",
        event_type=EventType.PROCESS_START,
        entities=[Entity(type=EntityType.FILE_HASH, value="5d41402abc4b2a76b9719d911017c592")],
    )
    assert score_notability(with_hash) > score_notability(plain)


def test_low_parse_confidence_scales_notability_down() -> None:
    certain = _event("a", event_type=EventType.AUTH_FAILURE, confidence=1.0)
    shaky = _event("b", event_type=EventType.AUTH_FAILURE, confidence=0.4)
    assert score_notability(shaky) < score_notability(certain)


def test_notability_stays_within_bounds() -> None:
    loud = _event(
        "a",
        event_type=EventType.PRIVILEGE_CHANGE,
        outcome="failure",
        entities=[
            Entity(type=EntityType.FILE_HASH, value="a" * 32),
            Entity(type=EntityType.IP_ADDRESS, value="203.0.113.9"),
            Entity(type=EntityType.URL, value="https://x.example.com"),
            Entity(type=EntityType.DOMAIN, value="x.example.com"),
            Entity(type=EntityType.PROCESS, value="bad.exe"),
        ],
    )
    assert 0.0 <= score_notability(loud) <= 1.0


# --- Correlation -----------------------------------------------------------


def test_events_sharing_a_host_are_correlated() -> None:
    events = [_event("a", host="web-01"), _event("b", minutes=5, host="web-01")]
    correlations = correlate_events(events, window=timedelta(minutes=30))

    assert len(correlations) == 1
    assert correlations[0].kind is CorrelationKind.SHARED_HOST
    assert correlations[0].key == "web-01"
    assert correlations[0].event_ids == ["a", "b"]


def test_events_sharing_an_actor_are_correlated() -> None:
    events = [_event("a", actor="deploy"), _event("b", minutes=2, actor="deploy")]
    kinds = {c.kind for c in correlate_events(events, window=timedelta(minutes=30))}
    assert CorrelationKind.SHARED_ACTOR in kinds


def test_events_sharing_an_address_are_correlated() -> None:
    ip = [Entity(type=EntityType.IP_ADDRESS, value="203.0.113.9")]
    events = [_event("a", entities=ip), _event("b", minutes=1, entities=ip)]
    kinds = {c.kind for c in correlate_events(events, window=timedelta(minutes=30))}
    assert CorrelationKind.SHARED_ADDRESS in kinds


def test_a_lone_event_is_not_a_correlation() -> None:
    assert correlate_events([_event("a", host="web-01")], window=timedelta(minutes=30)) == []


def test_events_beyond_the_window_form_separate_episodes() -> None:
    """A host active twice a week apart is two episodes, not one implausible cluster."""
    events = [
        _event("a", host="web-01"),
        _event("b", minutes=5, host="web-01"),
        _event("c", minutes=6000, host="web-01"),
        _event("d", minutes=6005, host="web-01"),
    ]
    host_correlations = [
        c
        for c in correlate_events(events, window=timedelta(minutes=30))
        if c.kind is CorrelationKind.SHARED_HOST
    ]
    assert len(host_correlations) == 2
    assert host_correlations[0].event_ids == ["a", "b"]
    assert host_correlations[1].event_ids == ["c", "d"]


def test_correlation_records_its_window_and_rationale() -> None:
    events = [_event("a", host="web-01"), _event("b", minutes=5, host="web-01")]
    correlation = correlate_events(events, window=timedelta(minutes=30))[0]

    assert correlation.window_start == BASE
    assert correlation.window_end == BASE + timedelta(minutes=5)
    assert "web-01" in correlation.rationale


def test_correlation_is_deterministic() -> None:
    events = [_event("a", host="web-01"), _event("b", minutes=5, host="web-01")]
    first = correlate_events(events, window=timedelta(minutes=30))
    second = correlate_events(events, window=timedelta(minutes=30))
    assert [c.correlation_id for c in first] == [c.correlation_id for c in second]


def test_event_ids_within_a_correlation_are_unique() -> None:
    """An event matching a key twice must not be counted twice."""
    ip = [Entity(type=EntityType.IP_ADDRESS, value="203.0.113.9")]
    events = [_event("a", host="web-01", entities=ip), _event("b", minutes=1, host="web-01")]
    for correlation in correlate_events(events, window=timedelta(minutes=30)):
        assert len(correlation.event_ids) == len(set(correlation.event_ids))


@pytest.mark.parametrize("minimum", [2, 3])
def test_minimum_event_threshold_is_respected(minimum: int) -> None:
    events = [_event("a", host="web-01"), _event("b", minutes=1, host="web-01")]
    correlations = correlate_events(events, window=timedelta(minutes=30), minimum_events=minimum)
    assert bool(correlations) is (minimum <= 2)

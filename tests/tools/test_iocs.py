"""Tests for IoC extraction, classification, and defanging."""

from datetime import UTC, datetime, timedelta

from models.logs import Entity, EntityType, EventType, LogFormat, LogSourceKind, NormalizedEvent
from models.threat import IocType
from tools.iocs import defang, enrichable, extract_iocs, is_internal_address

BASE = datetime(2026, 3, 4, 9, 0, tzinfo=UTC)


def _event(
    event_id: str, entities: list[tuple[EntityType, str]], *, minute: int = 0
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        record_id=event_id,
        source_id="hostlogs",
        source_kind=LogSourceKind.FILE,
        log_format=LogFormat.JSON,
        event_time=BASE + timedelta(minutes=minute),
        event_type=EventType.OTHER,
        entities=[Entity(type=kind, value=value) for kind, value in entities],
    )


def test_hosts_and_users_are_context_not_indicators() -> None:
    """Correlation keys are not findings; treating them as IoCs floods the output."""
    event = _event(
        "e1",
        [
            (EntityType.HOST, "web-01"),
            (EntityType.USER, "deploy"),
            (EntityType.IP_ADDRESS, "203.0.113.9"),
        ],
    )
    iocs = extract_iocs([event])

    assert [ioc.type for ioc in iocs] == [IocType.IP_ADDRESS]


def test_every_indicator_kind_is_recognized() -> None:
    event = _event(
        "e1",
        [
            (EntityType.IP_ADDRESS, "203.0.113.9"),
            (EntityType.DOMAIN, "evil.example"),
            (EntityType.URL, "http://evil.example/payload"),
            (EntityType.FILE_HASH, "a" * 64),
            (EntityType.FILE_PATH, "/tmp/dropper"),
            (EntityType.PROCESS, "mshta.exe"),
        ],
    )
    assert {ioc.type for ioc in extract_iocs([event])} == set(IocType)


def test_repeat_sightings_accumulate_events_and_a_time_span() -> None:
    events = [
        _event("e1", [(EntityType.IP_ADDRESS, "203.0.113.9")], minute=0),
        _event("e2", [(EntityType.IP_ADDRESS, "203.0.113.9")], minute=5),
        _event("e3", [(EntityType.IP_ADDRESS, "203.0.113.9")], minute=2),
    ]
    (ioc,) = extract_iocs(events)

    assert ioc.observation_count == 3
    assert ioc.event_ids == ["e1", "e2", "e3"]
    assert ioc.first_seen == BASE
    assert ioc.last_seen == BASE + timedelta(minutes=5)


def test_extraction_order_is_deterministic_and_most_seen_first() -> None:
    events = [
        _event("e1", [(EntityType.IP_ADDRESS, "203.0.113.9")], minute=0),
        _event("e2", [(EntityType.IP_ADDRESS, "203.0.113.9")], minute=1),
        _event("e3", [(EntityType.DOMAIN, "evil.example")], minute=2),
    ]
    assert [ioc.value for ioc in extract_iocs(events)] == ["203.0.113.9", "evil.example"]


def test_indicators_are_stored_defanged() -> None:
    event = _event("e1", [(EntityType.URL, "https://evil.example/payload")])
    (ioc,) = extract_iocs([event])

    assert ioc.value == "https://evil.example/payload"
    assert ioc.defanged == "hxxps://evil[.]example/payload"


def test_defang_neutralizes_schemes_dots_and_addresses() -> None:
    assert defang("http://bad.example") == "hxxp://bad[.]example"
    assert defang("203.0.113.9") == "203[.]0[.]113[.]9"
    assert defang("phish@bad.example") == "phish[at]bad[.]example"


def test_rfc1918_and_loopback_are_internal() -> None:
    for address in ("10.1.2.3", "172.16.0.9", "192.168.1.1", "127.0.0.1", "fd00::1"):
        assert is_internal_address(address), address


def test_documentation_ranges_are_not_treated_as_internal() -> None:
    """``ipaddress.is_private`` covers TEST-NET; the estate does not.

    Marking an external address internal is a silent failure in the dangerous
    direction: it is never enriched and never scrutinized.
    """
    for address in ("203.0.113.44", "198.51.100.7", "192.0.2.1", "8.8.8.8"):
        assert not is_internal_address(address), address


def test_configured_cidrs_extend_what_counts_as_internal() -> None:
    assert is_internal_address("198.51.100.7", ["198.51.100.0/24"])
    assert not is_internal_address("198.51.100.7", ["203.0.113.0/24"])


def test_a_malformed_cidr_is_ignored_rather_than_fatal() -> None:
    assert not is_internal_address("8.8.8.8", ["not-a-cidr", "10.0.0.0/8"])


def test_internal_naming_suffixes_are_internal() -> None:
    assert is_internal_address("dc01.corp")
    assert is_internal_address("printer.local")
    assert not is_internal_address("evil.example")


def test_only_addresses_and_domains_carry_an_inside_or_outside() -> None:
    event = _event(
        "e1",
        [
            (EntityType.IP_ADDRESS, "10.0.0.5"),
            (EntityType.FILE_PATH, "/etc/passwd"),
            (EntityType.PROCESS, "sshd"),
        ],
    )
    by_type = {ioc.type: ioc for ioc in extract_iocs([event])}

    assert by_type[IocType.IP_ADDRESS].internal is True
    assert by_type[IocType.FILE_PATH].internal is False
    assert by_type[IocType.PROCESS].internal is False


def test_internal_indicators_are_never_submitted_for_enrichment() -> None:
    """Enrichment must not leak internal topology to a third party."""
    event = _event(
        "e1",
        [
            (EntityType.IP_ADDRESS, "10.0.0.5"),
            (EntityType.IP_ADDRESS, "203.0.113.9"),
        ],
    )
    assert [ioc.value for ioc in enrichable(extract_iocs([event]))] == ["203.0.113.9"]


def test_paths_and_process_names_are_not_submitted_for_enrichment() -> None:
    """They routinely embed usernames and directory layout."""
    event = _event(
        "e1",
        [
            (EntityType.FILE_PATH, "/home/jsmith/.ssh/id_rsa"),
            (EntityType.PROCESS, "payroll_export.exe"),
            (EntityType.FILE_HASH, "b" * 64),
        ],
    )
    assert [ioc.type for ioc in enrichable(extract_iocs([event]))] == [IocType.FILE_HASH]


def test_extraction_never_assigns_a_reputation() -> None:
    """Observation is not judgement — reputation only ever comes from a source."""
    event = _event("e1", [(EntityType.IP_ADDRESS, "203.0.113.9")])
    (ioc,) = extract_iocs([event])

    assert ioc.reputation.value == "unknown"
    assert ioc.reputation_source is None
    assert ioc.enriched is False
    assert ioc.is_hostile is False


def test_no_events_yields_no_indicators() -> None:
    assert extract_iocs([]) == []

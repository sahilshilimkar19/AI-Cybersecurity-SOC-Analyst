"""Tests for report assembly: timeline, affected assets, citations."""

from datetime import UTC, datetime, timedelta

from models.enums import CveApplicability, SourceTrustTier
from models.logs import EventType, LogFormat, LogSourceKind, NormalizedEvent, TimelineEntry
from models.values import Citation
from models.vulnerability import (
    ApplicabilityEvidence,
    ApplicabilityReason,
    CveAssessment,
    CveRecord,
)
from tools.reporting import (
    assemble_timeline,
    citation_numbers,
    collect_affected_assets,
    compile_citations,
    reference_marks,
)

BASE = datetime(2026, 3, 4, 9, 0, tzinfo=UTC)


def _entry(event_id: str, *, minute: int = 0, notability: float = 0.5) -> TimelineEntry:
    return TimelineEntry(
        event_id=event_id,
        event_time=BASE + timedelta(minutes=minute),
        source_id="hostlogs",
        summary=f"event {event_id}",
        notability=notability,
    )


def _event(
    event_id: str, *, host: str | None = "web-01", minute: int = 0, raw_ref: str | None = None
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        record_id=event_id,
        source_id="hostlogs",
        source_kind=LogSourceKind.FILE,
        log_format=LogFormat.JSON,
        event_time=BASE + timedelta(minutes=minute),
        event_type=EventType.OTHER,
        host=host,
        raw_ref=raw_ref,
    )


def _citation(source_id: str, url: str | None = None, chunk_id: str | None = None) -> Citation:
    return Citation(source_id=source_id, source=source_id, url=url, chunk_id=chunk_id)


# --- Timeline ---------------------------------------------------------------


def test_the_timeline_is_ordered_chronologically() -> None:
    timeline, omitted = assemble_timeline(
        [_entry("c", minute=5), _entry("a", minute=1), _entry("b", minute=3)], limit=10
    )

    assert [entry.event_id for entry in timeline] == ["a", "b", "c"]
    assert omitted == 0


def test_repeated_entries_appear_once() -> None:
    timeline, _ = assemble_timeline([_entry("a"), _entry("a"), _entry("b", minute=1)], limit=10)
    assert [entry.event_id for entry in timeline] == ["a", "b"]


def test_truncation_is_counted_not_silent() -> None:
    """A reader who cannot see a timeline was cut reads its last row as the end."""
    entries = [_entry(f"e{index}", minute=index) for index in range(10)]
    timeline, omitted = assemble_timeline(entries, limit=4)

    assert len(timeline) == 4
    assert omitted == 6


def test_truncation_keeps_the_most_notable_not_the_earliest() -> None:
    """An attack's important moments are rarely its first few."""
    entries = [
        _entry("early", minute=0, notability=0.1),
        _entry("dull", minute=1, notability=0.1),
        _entry("loud", minute=9, notability=0.9),
    ]
    timeline, omitted = assemble_timeline(entries, limit=2)

    assert "loud" in {entry.event_id for entry in timeline}
    assert omitted == 1


def test_a_truncated_timeline_still_reads_forwards() -> None:
    entries = [
        _entry("late", minute=9, notability=0.9),
        _entry("early", minute=1, notability=0.8),
        _entry("dull", minute=5, notability=0.1),
    ]
    timeline, _ = assemble_timeline(entries, limit=2)
    assert [entry.event_id for entry in timeline] == ["early", "late"]


def test_raw_references_are_carried_so_a_row_can_be_walked_back() -> None:
    timeline, _ = assemble_timeline(
        [_entry("a")], limit=10, events=[_event("a", raw_ref="auth.log#L7")]
    )
    assert timeline[0].raw_ref == "auth.log#L7"


def test_an_entry_with_no_matching_event_carries_no_reference() -> None:
    timeline, _ = assemble_timeline([_entry("a")], limit=10, events=[])
    assert timeline[0].raw_ref is None


def test_an_empty_timeline_is_empty_not_an_error() -> None:
    assert assemble_timeline([], limit=10) == ([], 0)


# --- Affected assets --------------------------------------------------------


def test_assets_are_derived_from_the_events_that_named_them() -> None:
    assets = collect_affected_assets(
        [
            _event("a", host="web-01"),
            _event("b", host="web-01", minute=5),
            _event("c", host="db-01"),
        ]
    )
    by_host = {asset.hostname: asset for asset in assets}

    assert by_host["web-01"].event_count == 2
    assert by_host["web-01"].first_seen == BASE
    assert by_host["web-01"].last_seen == BASE + timedelta(minutes=5)
    assert by_host["db-01"].event_count == 1


def test_events_without_a_host_contribute_no_asset() -> None:
    assert collect_affected_assets([_event("a", host=None)]) == []


def test_critical_assets_lead_the_list() -> None:
    """The report should open with the machine an analyst must look at first."""
    events = [
        *[_event(f"w{index}", host="web-01") for index in range(5)],
        _event("d1", host="db-01"),
    ]
    assets = collect_affected_assets(events, critical_assets=["db-01"])

    assert assets[0].hostname == "db-01"
    assert assets[0].critical is True
    assert assets[1].critical is False


def test_confirmed_cves_attach_to_the_host_the_evidence_named() -> None:
    assessment = CveAssessment(
        record=CveRecord(cve_id="CVE-2021-44228"),
        applicability=CveApplicability.CONFIRMED,
        evidence=[
            ApplicabilityEvidence(
                reason=ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE,
                hostname="web-01",
                product="log4j",
                installed_version="2.14.1",
            )
        ],
    )
    (asset,) = collect_affected_assets([_event("a", host="web-01")], confirmed=[assessment])
    assert asset.confirmed_cve_ids == ["CVE-2021-44228"]


def test_a_vulnerable_host_with_no_events_still_appears() -> None:
    """The estate is affected whether or not the logs happened to mention it."""
    assessment = CveAssessment(
        record=CveRecord(cve_id="CVE-2021-44228"),
        applicability=CveApplicability.CONFIRMED,
        evidence=[
            ApplicabilityEvidence(
                reason=ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE,
                hostname="db-01",
                product="log4j",
                installed_version="2.14.1",
            )
        ],
    )
    assets = collect_affected_assets([_event("a", host="web-01")], confirmed=[assessment])
    assert {asset.hostname for asset in assets} == {"web-01", "db-01"}


# --- Citations --------------------------------------------------------------


def test_the_same_source_cited_twice_is_one_reference() -> None:
    compiled = compile_citations(
        [_citation("nvd", url="https://example/1")],
        [_citation("nvd", url="https://example/1"), _citation("mitre_cwe", url="https://x/2")],
    )
    assert [citation.source_id for citation in compiled] == ["nvd", "mitre_cwe"]


def test_numbering_is_stable_across_regenerations() -> None:
    """A report whose reference [3] means something else on Tuesday is not citable."""
    groups = [
        [_citation("mitre_attack", url="https://a"), _citation("nvd", url="https://b")],
        [_citation("mitre_cwe", url="https://c")],
    ]
    first = citation_numbers(compile_citations(*groups))
    second = citation_numbers(compile_citations(*groups))
    assert first == second


def test_references_are_numbered_from_one() -> None:
    numbers = citation_numbers(compile_citations([_citation("nvd", url="https://a")]))
    assert set(numbers.values()) == {1}


def test_the_same_source_pointing_at_different_passages_stays_distinct() -> None:
    compiled = compile_citations(
        [_citation("corpus", chunk_id="a#0"), _citation("corpus", chunk_id="b#0")]
    )
    assert len(compiled) == 2


def test_reference_marks_render_sorted_and_deduplicated() -> None:
    compiled = compile_citations(
        [
            _citation("a", url="https://1"),
            _citation("b", url="https://2"),
            _citation("c", url="https://3"),
        ]
    )
    numbers = citation_numbers(compiled)
    marks = reference_marks([compiled[2], compiled[0], compiled[2]], numbers)
    assert marks == "[1][3]"


def test_a_citation_absent_from_the_compiled_list_is_not_marked() -> None:
    numbers = citation_numbers(compile_citations([_citation("a", url="https://1")]))
    assert reference_marks([_citation("z", url="https://9")], numbers) == ""


def test_a_citation_with_neither_url_nor_chunk_still_identifies() -> None:
    compiled = compile_citations(
        [
            Citation(
                source_id="nvd",
                source="NVD",
                title="CVE-1",
                trust_tier=SourceTrustTier.AUTHORITATIVE,
            ),
            Citation(source_id="nvd", source="NVD", title="CVE-2"),
        ]
    )
    assert len(compiled) == 2

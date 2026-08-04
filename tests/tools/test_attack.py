"""Tests for the ATT&CK catalogue and the signal-to-technique mapper.

The catalogue is a pinned vocabulary. The property that matters most is the
negative one: an identifier that is not in it must be dropped, never described.
"""

import re

from models.threat import DetectionSignal
from tools.attack import (
    ATTACK_SOURCE_ID,
    TECHNIQUES,
    known_technique,
    map_techniques,
)

_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _signal(
    rule_id: str, technique_ids: list[str], *, weight: float = 6.0, events: list[str] | None = None
) -> DetectionSignal:
    return DetectionSignal(
        rule_id=rule_id,
        name=rule_id.replace("_", " "),
        description="test signal",
        weight=weight,
        event_ids=events or ["e1"],
        technique_ids=technique_ids,
    )


def test_catalogue_entries_are_well_formed() -> None:
    for technique_id, definition in TECHNIQUES.items():
        assert _TECHNIQUE_ID.match(technique_id), technique_id
        assert definition.technique_id == technique_id
        assert definition.name
        assert definition.tactics


def test_lookup_is_case_insensitive_and_misses_cleanly() -> None:
    assert known_technique("t1110") is not None
    assert known_technique("T9999") is None


def test_technique_urls_follow_the_attack_path_convention() -> None:
    assert TECHNIQUES["T1110"].url == "https://attack.mitre.org/techniques/T1110/"
    assert TECHNIQUES["T1059.001"].url == "https://attack.mitre.org/techniques/T1059/001/"


def test_an_uncatalogued_technique_is_dropped_not_invented() -> None:
    """The rule that stops a plausible-looking fabrication reaching a report."""
    mappings = map_techniques([_signal("bogus", ["T9999", "T1110"])])
    assert [mapping.technique_id for mapping in mappings] == ["T1110"]


def test_every_mapping_carries_a_resolvable_citation() -> None:
    (mapping,) = map_techniques([_signal("brute_force", ["T1110"])])

    assert mapping.citations
    citation = mapping.citations[0]
    assert citation.source_id == ATTACK_SOURCE_ID
    assert citation.url == "https://attack.mitre.org/techniques/T1110/"
    assert "T1110" in (citation.title or "")


def test_names_and_tactics_come_only_from_the_catalogue() -> None:
    (mapping,) = map_techniques([_signal("valid_accounts", ["T1078"])])
    assert mapping.name == TECHNIQUES["T1078"].name
    assert mapping.tactics == list(TECHNIQUES["T1078"].tactics)


def test_a_technique_serving_several_tactics_keeps_all_of_them() -> None:
    (mapping,) = map_techniques([_signal("valid_accounts", ["T1078"])])
    assert len(mapping.tactics) > 1


def test_signals_supporting_one_technique_are_aggregated() -> None:
    mappings = map_techniques(
        [
            _signal("brute_force", ["T1110"], events=["e1", "e2"]),
            _signal("breakthrough", ["T1110"], events=["e2", "e3"]),
        ]
    )
    (mapping,) = mappings
    assert mapping.event_ids == ["e1", "e2", "e3"]
    assert "brute force" in mapping.rationale
    assert "breakthrough" in mapping.rationale


def test_corroborated_techniques_are_more_confident() -> None:
    single = map_techniques([_signal("brute_force", ["T1110"])])[0]
    double = map_techniques(
        [_signal("brute_force", ["T1110"]), _signal("breakthrough", ["T1110"])]
    )[0]
    assert double.confidence > single.confidence


def test_confidence_never_reaches_certainty() -> None:
    """A rule match is evidence for a technique, not proof of one."""
    signals = [_signal(f"rule_{index}", ["T1110"], weight=10.0) for index in range(8)]
    assert map_techniques(signals)[0].confidence <= 0.95


def test_mappings_are_ordered_deterministically() -> None:
    signals = [_signal("a", ["T1110"]), _signal("b", ["T1027"]), _signal("c", ["T1070"])]
    assert [mapping.technique_id for mapping in map_techniques(signals)] == [
        "T1027",
        "T1070",
        "T1110",
    ]


def test_no_signals_map_to_no_techniques() -> None:
    assert map_techniques([]) == []

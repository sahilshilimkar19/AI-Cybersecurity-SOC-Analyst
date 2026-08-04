"""Tests for the CWE weakness catalogue.

Like the ATT&CK catalogue, the property that matters most is the negative one: an
identifier absent from the table gets no name and no explanation rather than an
invented one.
"""

import re

import pytest

from tools.cwe import CWE_SOURCE_ID, WEAKNESSES, explain, known_weakness, normalize_cwe_id

_CWE_ID = re.compile(r"^CWE-\d+$")


def test_catalogue_entries_are_well_formed() -> None:
    for cwe_id, definition in WEAKNESSES.items():
        assert _CWE_ID.match(cwe_id), cwe_id
        assert definition.cwe_id == cwe_id
        assert definition.name
        assert definition.explanation.endswith(".")


def test_explanations_are_written_for_a_non_specialist() -> None:
    """The dossier puts these in front of readers who are not researchers."""
    explanation = explain("CWE-502")
    assert explanation is not None
    assert "attacker-controlled data" in explanation


@pytest.mark.parametrize("raw", ["CWE-79", "cwe-79", " CWE-79 "])
def test_lookup_tolerates_spelling_and_whitespace(raw: str) -> None:
    definition = known_weakness(raw)
    assert definition is not None
    assert definition.cwe_id == "CWE-79"


def test_an_uncatalogued_weakness_is_not_described() -> None:
    assert known_weakness("CWE-99999") is None
    assert explain("CWE-99999") is None


def test_something_that_is_not_a_cwe_identifier_is_rejected() -> None:
    assert normalize_cwe_id("not-a-cwe") is None
    assert known_weakness("T1110") is None


def test_nvd_sentinels_read_as_themselves_rather_than_as_a_miss() -> None:
    """ "Not categorized" is a fact about the record, not a failed lookup."""
    assert explain("NVD-CWE-noinfo") == (
        "The vulnerability record carries no weakness classification."
    )
    assert explain("NVD-CWE-Other") is not None


def test_every_weakness_carries_a_resolvable_citation() -> None:
    citation = WEAKNESSES["CWE-89"].citation()

    assert citation.source_id == CWE_SOURCE_ID
    assert citation.url == "https://cwe.mitre.org/data/definitions/89.html"
    assert "CWE-89" in (citation.title or "")

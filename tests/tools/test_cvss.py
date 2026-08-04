"""Tests for the CVSS v3.1 interpreter.

The scoring cases are published vectors with published scores, taken from the
specification's examples and from well-known advisories. That is the point of
implementing the formula rather than echoing a feed: it can be checked against an
external authority, and these assertions are that check.
"""

import pytest

from models.enums import Severity
from tools.cvss import base_score, interpret, narrate, parse_vector

LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
FULL_UNCHANGED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL_ADMIN = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
REFLECTED_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        (LOG4SHELL, 10.0),
        (FULL_UNCHANGED, 9.8),
        (LOCAL_ADMIN, 7.8),
        (REFLECTED_XSS, 6.1),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # v3.0 uses the same base formula, so both versions are accepted.
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ],
)
def test_base_scores_match_published_values(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


def test_rounding_follows_the_specification_not_ordinary_rounding() -> None:
    """The spec rounds *up* to one decimal; ordinary rounding disagrees at edges."""
    # 6.0067 -> 6.1, not 6.0.
    assert base_score(REFLECTED_XSS) == 6.1


def test_no_impact_scores_zero_regardless_of_exploitability() -> None:
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_parsing_yields_long_form_metric_names() -> None:
    metrics = parse_vector(LOG4SHELL)
    assert metrics == {
        "AV": "NETWORK",
        "AC": "LOW",
        "PR": "NONE",
        "UI": "NONE",
        "S": "CHANGED",
        "C": "HIGH",
        "I": "HIGH",
        "A": "HIGH",
    }


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "nonsense",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        # An undefined metric value.
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        # A missing required metric.
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
    ],
)
def test_an_unreadable_vector_refuses_rather_than_guessing(vector: str) -> None:
    """A partly-understood vector scored as if complete understates the unknown part."""
    assert parse_vector(vector) is None
    assert base_score(vector) is None
    assert interpret(vector) is None


def test_interpretation_carries_metrics_score_and_severity() -> None:
    metrics = interpret(LOG4SHELL)

    assert metrics is not None
    assert metrics.version == "3.1"
    assert metrics.vector == LOG4SHELL
    assert metrics.base_score == 10.0
    assert metrics.severity is Severity.CRITICAL
    assert metrics.attack_vector == "NETWORK"
    assert metrics.scope == "CHANGED"


def test_a_reported_score_that_agrees_is_kept() -> None:
    metrics = interpret(FULL_UNCHANGED, reported_score=9.8)
    assert metrics is not None
    assert metrics.base_score == 9.8


def test_a_reported_score_that_disagrees_loses_to_the_vector() -> None:
    """The vector is the primary artifact; a mismatched score is a feed error."""
    metrics = interpret(FULL_UNCHANGED, reported_score=4.2)
    assert metrics is not None
    assert metrics.base_score == 9.8


def test_severity_bands_are_the_cvss_bands() -> None:
    assert interpret(FULL_UNCHANGED).severity is Severity.CRITICAL  # type: ignore[union-attr]
    assert interpret(LOCAL_ADMIN).severity is Severity.HIGH  # type: ignore[union-attr]
    assert interpret(REFLECTED_XSS).severity is Severity.MEDIUM  # type: ignore[union-attr]


def test_the_internet_facing_combination_is_flagged() -> None:
    """Network reach with no credentials and no user interaction is the worst case."""
    assert interpret(FULL_UNCHANGED).remotely_exploitable_without_credentials  # type: ignore[union-attr]
    assert not interpret(LOCAL_ADMIN).remotely_exploitable_without_credentials  # type: ignore[union-attr]


def test_the_narrative_is_readable_by_a_non_specialist() -> None:
    narrative = interpret(FULL_UNCHANGED).narrative  # type: ignore[union-attr]

    assert "9.8/10" in narrative
    assert "over the network" in narrative
    assert "without any credentials" in narrative
    assert "without any user interaction" in narrative
    assert "confidentiality (high)" in narrative


def test_the_narrative_calls_out_user_interaction_and_scope_change() -> None:
    narrative = interpret(REFLECTED_XSS).narrative  # type: ignore[union-attr]

    assert "tricked into acting" in narrative
    assert "beyond the vulnerable component" in narrative


def test_the_narrative_calls_out_high_attack_complexity() -> None:
    narrative = interpret("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H").narrative  # type: ignore[union-attr]
    assert "conditions outside the attacker's control" in narrative


def test_a_zero_impact_vector_narrates_honestly() -> None:
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert metrics is not None
    assert "no direct impact" in narrate(metrics, 0.0)


def test_interpretation_is_deterministic() -> None:
    first, second = interpret(LOG4SHELL), interpret(LOG4SHELL)
    assert first is not None and second is not None
    assert first.model_dump() == second.model_dump()

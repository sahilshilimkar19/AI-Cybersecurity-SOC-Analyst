"""CVSS v3.1 vector parsing, scoring, and plain-language interpretation.

The CVE Research agent's job is not only to find vulnerabilities but to
*explain* them (SAD §2.3), and a bare "9.8" explains nothing. This module turns a
vector string into three things: its parsed metrics, the base score they imply,
and a sentence a non-specialist can act on.

Two decisions are worth stating:

* **The score is computed, not merely echoed.** The v3.1 base formula is public,
  fully specified arithmetic, so implementing it lets the platform verify a score
  a feed supplied and produce one when a feed supplied only a vector. A
  vulnerability record whose stated score disagrees with its own vector is a data
  problem worth surfacing, not one to propagate.
* **Parsing refuses rather than guesses.** An unrecognized or incomplete vector
  returns ``None``. A partially-understood vector scored as though it were
  complete would understate severity in exactly the cases where the unfamiliar
  metric was the important one.

Scores map onto the shared :class:`~models.enums.Severity` scale through
``tools.severity.severity_level``, whose bands are the CVSS bands — so a CVE's
severity and an incident's severity are read the same way.
"""

from __future__ import annotations

import math
import re

from models.vulnerability import CvssMetrics
from tools.severity import severity_level

# --- The v3.1 specification -------------------------------------------------

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# Privileges Required is the one metric whose weight depends on Scope: a changed
# scope means the privileges held were in a *different* security authority, which
# makes holding them less of a barrier.
_PRIVILEGES_REQUIRED: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

_SCOPE = {"U", "C"}

# Long names for the abbreviations, used in the parsed metrics and the narrative.
_NAMES: dict[str, dict[str, str]] = {
    "AV": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
    "AC": {"L": "LOW", "H": "HIGH"},
    "PR": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    "UI": {"N": "NONE", "R": "REQUIRED"},
    "S": {"U": "UNCHANGED", "C": "CHANGED"},
    "C": {"H": "HIGH", "L": "LOW", "N": "NONE"},
    "I": {"H": "HIGH", "L": "LOW", "N": "NONE"},
    "A": {"H": "HIGH", "L": "LOW", "N": "NONE"},
}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_VECTOR = re.compile(r"^CVSS:(3\.[01])/(?P<body>[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])*)$")

# Phrasings for the narrative, keyed by metric value.
_REACH = {
    "NETWORK": "over the network",
    "ADJACENT_NETWORK": "from an adjacent network",
    "LOCAL": "with local access to the host",
    "PHYSICAL": "with physical access to the device",
}
_PRIVILEGE_PHRASE = {
    "NONE": "without any credentials",
    "LOW": "with ordinary user credentials",
    "HIGH": "with administrative credentials",
}


def parse_vector(vector: str) -> dict[str, str] | None:
    """Parse a CVSS v3.x vector into long-form metric names.

    Returns ``None`` for anything unrecognized, incomplete, or carrying a metric
    value the specification does not define — a vector understood only in part is
    not understood.
    """
    match = _VECTOR.match(vector.strip())
    if match is None:
        return None

    raw: dict[str, str] = {}
    for part in match.group("body").split("/"):
        key, _, value = part.partition(":")
        raw[key] = value

    metrics: dict[str, str] = {}
    for metric in _REQUIRED_METRICS:
        value = raw.get(metric)
        if value is None or value not in _NAMES[metric]:
            return None
        metrics[metric] = _NAMES[metric][value]
    return metrics


def base_score(vector: str) -> float | None:
    """Compute the CVSS v3.1 base score for a vector, or ``None`` if unparseable."""
    match = _VECTOR.match(vector.strip())
    if match is None or parse_vector(vector) is None:
        return None

    raw = dict(part.split(":", 1) for part in match.group("body").split("/"))
    scope = raw["S"]
    if scope not in _SCOPE:
        return None

    impact_sub = 1.0 - (
        (1.0 - _WEIGHTS["C"][raw["C"]])
        * (1.0 - _WEIGHTS["I"][raw["I"]])
        * (1.0 - _WEIGHTS["A"][raw["A"]])
    )
    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22
        * _WEIGHTS["AV"][raw["AV"]]
        * _WEIGHTS["AC"][raw["AC"]]
        * _PRIVILEGES_REQUIRED[scope][raw["PR"]]
        * _WEIGHTS["UI"][raw["UI"]]
    )
    combined = impact + exploitability
    if scope == "C":
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def interpret(vector: str, *, reported_score: float | None = None) -> CvssMetrics | None:
    """Parse, score, and narrate a CVSS vector.

    ``reported_score`` is the score the feed published. It is preferred when it
    agrees with the computed one; a disagreement keeps the **computed** score,
    because the vector is the primary artifact and a mismatched score is a data
    error in the feed rather than an additional fact.
    """
    metrics = parse_vector(vector)
    computed = base_score(vector)
    if metrics is None or computed is None:
        return None

    version = vector.strip().split("/", 1)[0].removeprefix("CVSS:")
    score = computed
    if reported_score is not None and abs(reported_score - computed) < 0.05:
        score = round(reported_score, 1)

    return CvssMetrics(
        version=version,
        vector=vector.strip(),
        base_score=score,
        severity=severity_level(score),
        attack_vector=metrics["AV"],
        attack_complexity=metrics["AC"],
        privileges_required=metrics["PR"],
        user_interaction=metrics["UI"],
        scope=metrics["S"],
        confidentiality=metrics["C"],
        integrity=metrics["I"],
        availability=metrics["A"],
        narrative=narrate(metrics, score),
    )


def narrate(metrics: dict[str, str], score: float) -> str:
    """Describe a parsed vector in language an analyst can hand to a manager."""
    reach = _REACH.get(metrics["AV"], "by an unspecified route")
    privileges = _PRIVILEGE_PHRASE.get(metrics["PR"], "with unspecified privileges")
    interaction = (
        " and only if a user is tricked into acting"
        if metrics["UI"] == "REQUIRED"
        else " and without any user interaction"
    )
    complexity = (
        " Exploitation depends on conditions outside the attacker's control."
        if metrics["AC"] == "HIGH"
        else ""
    )
    scope = (
        " A successful attack reaches beyond the vulnerable component into other systems."
        if metrics["S"] == "CHANGED"
        else ""
    )
    return (
        f"Scored {score}/10 ({severity_level(score).value}). "
        f"Exploitable {reach} {privileges}{interaction}. "
        f"Impact: {_impact_phrase(metrics)}.{complexity}{scope}"
    ).strip()


def _impact_phrase(metrics: dict[str, str]) -> str:
    """Summarize which of confidentiality, integrity, and availability suffer."""
    labels = {"C": "confidentiality", "I": "integrity", "A": "availability"}
    affected = [
        f"{labels[metric]} ({metrics[metric].lower()})"
        for metric in ("C", "I", "A")
        if metrics[metric] != "NONE"
    ]
    return ", ".join(affected) if affected else "no direct impact on the affected component"


def _roundup(value: float) -> float:
    """The specification's rounding: the smallest one-decimal number >= value.

    Ordinary rounding is not equivalent — the spec is explicit about this — and
    using it produces scores that disagree with every published CVSS calculator
    at the boundaries.
    """
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0

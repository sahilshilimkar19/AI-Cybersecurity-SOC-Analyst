"""MITRE ATT&CK technique catalogue and mapper (EDS §4.3 required tools).

Mapping observed behavior to ATT&CK is what turns "several failed logins" into a
statement an analyst can act on and compare across incidents. The mapping is only
as trustworthy as its vocabulary, so the vocabulary is **pinned here** rather than
generated: a technique identifier that is not in this catalogue is dropped, never
described from imagination. That single rule is what stops a plausible-looking
``T9999 — Advanced Persistence`` from ever reaching a report.

Every mapped technique carries a citation to its ATT&CK page, so the claim
"this is T1110" is checkable by following a link rather than by trusting the
platform (invariant #4). The catalogue is a curated subset covering the
behaviors the detection rules recognize; it grows with the rules, and the RAG
corpus supplies the deeper narrative context around it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from config.logging import get_logger
from models.enums import SourceTrustTier
from models.threat import TechniqueMapping
from models.values import Citation

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from models.threat import DetectionSignal

_logger = get_logger(__name__)

ATTACK_SOURCE_ID = "mitre_attack"
ATTACK_SOURCE_NAME = "MITRE ATT&CK"
_ATTACK_BASE_URL = "https://attack.mitre.org/techniques"


@dataclass(frozen=True)
class TechniqueDefinition:
    """One catalogued ATT&CK technique."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        """The canonical ATT&CK page, including the sub-technique path form."""
        base, _, sub = self.technique_id.partition(".")
        return f"{_ATTACK_BASE_URL}/{base}/{sub}/" if sub else f"{_ATTACK_BASE_URL}/{base}/"

    def citation(self) -> Citation:
        """A resolvable reference supporting the mapping."""
        return Citation(
            source_id=ATTACK_SOURCE_ID,
            source=ATTACK_SOURCE_NAME,
            url=self.url,
            title=f"{self.technique_id} — {self.name}",
            trust_tier=SourceTrustTier.AUTHORITATIVE,
        )


# The pinned vocabulary. Names and tactics follow ATT&CK Enterprise; adding a
# technique here is the only way a detection rule can reference one.
_CATALOGUE: tuple[TechniqueDefinition, ...] = (
    TechniqueDefinition("T1021", "Remote Services", ("Lateral Movement",)),
    TechniqueDefinition("T1027", "Obfuscated Files or Information", ("Defense Evasion",)),
    TechniqueDefinition("T1041", "Exfiltration Over C2 Channel", ("Exfiltration",)),
    TechniqueDefinition(
        "T1053", "Scheduled Task/Job", ("Execution", "Persistence", "Privilege Escalation")
    ),
    TechniqueDefinition("T1059", "Command and Scripting Interpreter", ("Execution",)),
    TechniqueDefinition(
        "T1059.001", "Command and Scripting Interpreter: PowerShell", ("Execution",)
    ),
    TechniqueDefinition(
        "T1068", "Exploitation for Privilege Escalation", ("Privilege Escalation",)
    ),
    TechniqueDefinition("T1070", "Indicator Removal", ("Defense Evasion",)),
    TechniqueDefinition(
        "T1070.001", "Indicator Removal: Clear Windows Event Logs", ("Defense Evasion",)
    ),
    TechniqueDefinition("T1071", "Application Layer Protocol", ("Command and Control",)),
    TechniqueDefinition(
        "T1078",
        "Valid Accounts",
        ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
    ),
    TechniqueDefinition("T1098", "Account Manipulation", ("Persistence", "Privilege Escalation")),
    TechniqueDefinition("T1105", "Ingress Tool Transfer", ("Command and Control",)),
    TechniqueDefinition("T1110", "Brute Force", ("Credential Access",)),
    TechniqueDefinition("T1136", "Create Account", ("Persistence",)),
    TechniqueDefinition("T1218", "System Binary Proxy Execution", ("Defense Evasion",)),
    TechniqueDefinition(
        "T1543", "Create or Modify System Process", ("Persistence", "Privilege Escalation")
    ),
    TechniqueDefinition(
        "T1548", "Abuse Elevation Control Mechanism", ("Privilege Escalation", "Defense Evasion")
    ),
    TechniqueDefinition("T1562", "Impair Defenses", ("Defense Evasion",)),
    TechniqueDefinition("T1569", "System Services", ("Execution",)),
)

TECHNIQUES: dict[str, TechniqueDefinition] = {item.technique_id: item for item in _CATALOGUE}


def known_technique(technique_id: str) -> TechniqueDefinition | None:
    """Look a technique up, returning ``None`` for anything not catalogued."""
    return TECHNIQUES.get(technique_id.upper())


def map_techniques(signals: Sequence[DetectionSignal]) -> list[TechniqueMapping]:
    """Map fired detection signals onto ATT&CK techniques.

    Signals are aggregated per technique so one technique supported by three
    independent behaviors reads as stronger than one supported by a single rule.
    Confidence rises with corroboration and with the strength of the contributing
    signals, and is capped short of certainty: a rule match is evidence for a
    technique, not proof of one.
    """
    grouped: dict[str, list[DetectionSignal]] = {}
    for signal in signals:
        for technique_id in signal.technique_ids:
            definition = known_technique(technique_id)
            if definition is None:
                _logger.warning(
                    "attack_technique_not_catalogued",
                    technique_id=technique_id,
                    rule_id=signal.rule_id,
                )
                continue
            grouped.setdefault(definition.technique_id, []).append(signal)

    mappings: list[TechniqueMapping] = []
    for technique_id, contributing in sorted(grouped.items()):
        definition = TECHNIQUES[technique_id]
        mappings.append(
            TechniqueMapping(
                technique_id=technique_id,
                name=definition.name,
                tactics=list(definition.tactics),
                rationale="; ".join(signal.name for signal in contributing),
                event_ids=_unique_event_ids(contributing),
                confidence=_confidence(contributing),
                citations=[definition.citation()],
            )
        )
    return mappings


def _confidence(signals: Sequence[DetectionSignal]) -> float:
    """Corroboration plus signal strength, capped below certainty."""
    strongest = max(signal.weight for signal in signals)
    corroboration = 0.12 * (len(signals) - 1)
    return round(min(0.95, 0.40 + strongest / 20.0 + corroboration), 4)


def _unique_event_ids(signals: Iterable[DetectionSignal]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for signal in signals:
        for event_id in signal.event_ids:
            if event_id in seen:
                continue
            seen.add(event_id)
            ordered.append(event_id)
    return ordered

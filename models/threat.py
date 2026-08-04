"""Contracts for threat detection (EDS §4.3, SAD §2.2).

The shapes flowing through the Threat Detector: a correlated evidence picture in,
an assessment out. Four rules are encoded in these types rather than left to
convention, because each one is a place where a detector can quietly become
untrustworthy:

* **Reputation is never invented.** :class:`IocIndicator` starts at
  ``UNKNOWN`` reputation with ``enriched=False``. A reputation can only be set
  together with the source that asserted it, so "we did not check" can never be
  read as "it is clean" (SAD §2.2 failure handling).
* **Evidence is separated from inference.** Every statement the agent makes is an
  :class:`AssessmentClaim` tagged as an observation or an inference, so a reader
  can always tell what was seen from what was concluded (EDS §4.3 validation).
* **Findings point back at the evidence.** Signals, technique mappings, and
  indicators all carry the ``event_ids`` they rest on, so any conclusion can be
  walked back to the log lines that produced it.
* **Escalation is part of the output.** An ambiguous, high-impact case says so in
  the contract rather than relying on a caller to notice.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from models.base import DomainModel
from models.enums import EnrichmentStatus, Severity, TriagePriority, Verdict
from models.values import Citation


class IocType(StrEnum):
    """Kinds of indicator the detector extracts from evidence."""

    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    PROCESS = "process"


class IocReputation(StrEnum):
    """What an intel source says about an indicator.

    ``UNKNOWN`` is the default and also the honest answer when enrichment was
    unavailable — it is never upgraded by inference.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"


class ClaimKind(StrEnum):
    """Whether a statement records something observed or something concluded."""

    OBSERVATION = "observation"
    INFERENCE = "inference"


class IocIndicator(DomainModel):
    """An indicator of compromise observed in the evidence.

    ``value`` is the indicator as it appeared; ``defanged`` is the render-safe
    form used anywhere a human might click it. ``enriched`` distinguishes "an
    intel source told us this" from "nobody asked".
    """

    type: IocType
    value: str
    defanged: str
    event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    observation_count: int = Field(default=0, ge=0)
    # Whether the address/host is internal to the estate. Internal indicators are
    # kept as pivots but are not sent to third-party intel services.
    internal: bool = False
    reputation: IocReputation = IocReputation.UNKNOWN
    reputation_source: str | None = None
    reputation_detail: str | None = None
    enriched: bool = False

    @property
    def is_hostile(self) -> bool:
        """Whether an intel source actually asserted this indicator is bad."""
        return self.enriched and self.reputation in {
            IocReputation.MALICIOUS,
            IocReputation.SUSPICIOUS,
        }


class DetectionSignal(DomainModel):
    """One detection heuristic that fired, and the evidence that made it fire."""

    rule_id: str
    name: str
    description: str
    # Contribution to the severity score, in CVSS-like 0..10 units.
    weight: float = Field(ge=0.0, le=10.0)
    event_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    detail: str = ""


class TechniqueMapping(DomainModel):
    """An observed behavior mapped to a MITRE ATT&CK technique.

    ``name`` and ``tactics`` are only ever filled from the pinned catalogue, so an
    unrecognized identifier is dropped rather than described from imagination.
    A technique legitimately serves several tactics (valid accounts are both
    persistence and privilege escalation), so the tactic is a list, not a choice.
    """

    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    rationale: str = ""
    event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    citations: list[Citation] = Field(default_factory=list)


class SeverityAssessment(DomainModel):
    """Scored severity with the factors that produced it.

    The 0-10 scale and its bands mirror CVSS so a severity here reads the same way
    as a severity on a CVE, and ``factors`` records the arithmetic so a human can
    disagree with it specifically rather than in general.
    """

    score: float = Field(ge=0.0, le=10.0)
    level: Severity
    rationale: str = ""
    factors: list[str] = Field(default_factory=list)


class AssessmentClaim(DomainModel):
    """One statement, explicitly labelled as observed or inferred."""

    kind: ClaimKind
    statement: str
    event_ids: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)


class ThreatDetectionRequest(DomainModel):
    """Input to the Threat Detector (EDS §4.3 input schema).

    Carries the Log Analyzer's output plus the estate context needed to tell an
    internal address from an external one. Retrieved detection knowledge is not
    passed in: the agent retrieves it through the read-only knowledge tier, so the
    caller cannot substitute the corpus the agent reasons from.
    """

    investigation_id: str
    events: list[dict[str, object]] = Field(default_factory=list)
    timeline: list[dict[str, object]] = Field(default_factory=list)
    correlations: list[dict[str, object]] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    # CIDR blocks considered internal; indicators inside them are never submitted
    # to third-party enrichment.
    internal_networks: list[str] = Field(default_factory=list)
    # Hostnames of assets whose compromise is materially worse, used for triage.
    critical_assets: list[str] = Field(default_factory=list)


class ThreatDetectionResult(DomainModel):
    """Output of the Threat Detector (EDS §4.3 output schema)."""

    investigation_id: str
    verdict: Verdict = Verdict.BENIGN
    severity: SeverityAssessment
    triage_priority: TriagePriority = TriagePriority.LOW
    iocs: list[IocIndicator] = Field(default_factory=list)
    attack_techniques: list[TechniqueMapping] = Field(default_factory=list)
    signals: list[DetectionSignal] = Field(default_factory=list)
    claims: list[AssessmentClaim] = Field(default_factory=list)
    enrichment_status: EnrichmentStatus = EnrichmentStatus.UNAVAILABLE
    # Set when the case is ambiguous but high-impact: the human decides, and the
    # gate is told this is not a routine approval (SAD §2.2).
    escalation_required: bool = False
    escalation_reason: str | None = None
    knowledge_grounded: bool = False
    citations: list[Citation] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @property
    def observations(self) -> list[AssessmentClaim]:
        """The claims that record what was seen."""
        return [claim for claim in self.claims if claim.kind is ClaimKind.OBSERVATION]

    @property
    def inferences(self) -> list[AssessmentClaim]:
        """The claims that record what was concluded."""
        return [claim for claim in self.claims if claim.kind is ClaimKind.INFERENCE]

    @property
    def hostile_iocs(self) -> list[IocIndicator]:
        """Indicators an intel source actually flagged (never inferred)."""
        return [ioc for ioc in self.iocs if ioc.is_hostile]

"""Contracts for remediation recommendations (EDS §4.6, SAD §2.5).

The shapes flowing through the Patch Recommendation agent: findings in, a
prioritized remediation plan out — **for a human to review and execute**.

This is the module where the platform's central invariant stops being a policy
and becomes a shape. The agents before this one describe the world; this one
proposes changing it, which is exactly where an assistive system quietly becomes
an autonomous one. Three rules are therefore encoded in the types rather than
left to the agent's discretion:

* **A recommendation carries no executable.** There is no ``command``,
  ``script``, or ``playbook_id`` field, and there never should be. ``steps`` are
  instructions written for a person. A structure that cannot hold a runnable
  artifact cannot be wired to a runner by a later change that nobody reviewed
  carefully.
* **Human approval is not a flag that can be cleared.**
  ``requires_human_approval`` is ``Literal[True]``: it is not a default that a
  caller can override, it is the only value the type admits (invariant #1, #2).
* **Nothing is proposed without a reason and a source.** A validator refuses a
  recommendation with an empty rationale or no citation. "Patch it" is not
  guidance; guidance says what to change, why, and on whose authority (SAD §2.5).

``RiskScore`` is kept separate from severity on purpose. Severity says how bad
the flaw is; risk says how much it matters *here* — the same CVE is a different
problem on an internet-facing production host than on a lab VM.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from models.base import DomainModel
from models.enums import ApprovalStatus, RecommendationType, Severity, TriagePriority
from models.values import Citation


class RemediationConfidence(StrEnum):
    """How well-grounded a recommendation is.

    ``GENERIC`` is the honest label for the conservative fallback the spec
    requires when remediation knowledge is thin (SAD §2.5): sound general
    hardening, not advice tailored to this product and version. Presenting it
    unlabelled beside a vendor-specified fix is how a stopgap becomes a fix.
    """

    VENDOR_SPECIFIC = "vendor_specific"
    CLASS_SPECIFIC = "class_specific"
    GENERIC = "generic"


class RiskFactor(DomainModel):
    """One contribution to a risk score, named so it can be argued with."""

    name: str
    weight: float
    detail: str = ""


class RiskScore(DomainModel):
    """Composite risk for one finding, on the same 0-10 scale as severity.

    Severity and risk are deliberately different numbers. A critical CVE on a
    decommissioned lab box and a medium one on the payment gateway do not deserve
    the same queue position, and a system that cannot express that difference
    makes analysts re-derive it by hand every time.
    """

    score: float = Field(ge=0.0, le=10.0)
    level: Severity
    rationale: str = ""
    factors: list[RiskFactor] = Field(default_factory=list)


class RemediationSupport(DomainModel):
    """What this recommendation is answering.

    Identifiers rather than prose, so a reader can check that the fix addresses
    a finding the investigation actually made.
    """

    cve_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    signal_rule_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Whether this recommendation answers nothing the investigation found."""
        return not (self.cve_ids or self.technique_ids or self.signal_rule_ids or self.cwe_ids)


class RemediationRecommendation(DomainModel):
    """One proposed remediation, framed as advice for a human.

    ``steps`` are written for a person to carry out. There is no field capable of
    holding something a machine could run, which is the point: the structure
    itself refuses to become an automation payload.
    """

    action: str
    type: RecommendationType
    priority: TriagePriority
    risk: RiskScore
    rationale: str
    expected_impact: str | None = None
    # Human-executable steps. Instructions, never commands to be dispatched.
    steps: list[str] = Field(default_factory=list)
    # How the analyst confirms the change actually took effect.
    verification: str | None = None
    targets: list[str] = Field(default_factory=list)
    support: RemediationSupport = Field(default_factory=RemediationSupport)
    grounding: RemediationConfidence = RemediationConfidence.GENERIC
    citations: list[Citation] = Field(default_factory=list)
    # Not a default a caller may override — the only value this field admits.
    requires_human_approval: Literal[True] = True
    approval_status: ApprovalStatus = ApprovalStatus.PENDING

    @model_validator(mode="after")
    def _justified_and_sourced(self) -> RemediationRecommendation:
        """Refuse a recommendation that cannot say why, or on whose authority.

        SAD §2.5 requires the rationale *and* the source on every recommendation.
        Enforced here because an unjustified change request is one an analyst
        either applies blindly or ignores, and both outcomes are bad.
        """
        if not self.rationale.strip():
            raise ValueError(f"remediation {self.action!r} carries no rationale")
        if not self.citations:
            raise ValueError(f"remediation {self.action!r} cites no source")
        return self

    @model_validator(mode="after")
    def _agents_cannot_pre_approve(self) -> RemediationRecommendation:
        """An agent may propose; only a human may approve (invariant #1).

        Without this, a recommendation could be constructed already approved and
        travel through the gate as though a person had seen it.
        """
        if self.approval_status is not ApprovalStatus.PENDING:
            raise ValueError(
                f"remediation {self.action!r} was created with approval_status "
                f"{self.approval_status.value!r}; recommendations are always proposed pending, "
                "and only a recorded human decision may change that"
            )
        return self


class RemediationPlanRequest(DomainModel):
    """Input to the Patch Recommendation agent (EDS §4.6 input schema)."""

    investigation_id: str
    threat_assessment: dict[str, object] | None = None
    vulnerability_dossier: dict[str, object] | None = None
    assets: list[dict[str, object]] = Field(default_factory=list)
    critical_assets: list[str] = Field(default_factory=list)
    # Bounds how many findings are turned into recommendations, so a noisy
    # investigation produces a work list rather than a wall.
    max_recommendations: int = Field(default=20, ge=1)


class RemediationPlan(DomainModel):
    """Output of the Patch Recommendation agent (EDS §4.6 output schema)."""

    investigation_id: str
    recommendations: list[RemediationRecommendation] = Field(default_factory=list)
    overall_risk: RiskScore | None = None
    # Stated on the plan as well as on each item, because the plan is what gets
    # handed to a human and the guarantee has to be legible at that level too.
    requires_human_approval: Literal[True] = True
    # Set when the plan rests on generic hardening rather than product-specific
    # guidance, so thin knowledge is visible rather than inferred from wording.
    knowledge_limited: bool = False
    notes: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    version: int = Field(default=1, ge=1)

    @property
    def is_empty(self) -> bool:
        """Whether the investigation surfaced nothing to remediate."""
        return not self.recommendations

    @property
    def highest_priority(self) -> TriagePriority | None:
        """The most urgent recommendation's priority, or ``None`` if the plan is empty."""
        order = [
            TriagePriority.URGENT,
            TriagePriority.HIGH,
            TriagePriority.MEDIUM,
            TriagePriority.LOW,
        ]
        present = {item.priority for item in self.recommendations}
        return next((priority for priority in order if priority in present), None)

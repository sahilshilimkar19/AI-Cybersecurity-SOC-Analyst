"""Persisting remediation recommendations (invariants #1, #2, #7).

The Patch Recommendation agent *proposes*; the backend *writes*; a human
*approves*. Three separate steps, and this module is careful about the seam
between the second and the third, because that seam is where an assistive
platform would become an autonomous one.

Every row is written ``PENDING`` and ``requires_human_approval=True`` regardless
of what the agent produced. :func:`decide_recommendation` is the only path that
changes an approval status, it requires an actor, and it refuses to re-decide
something already decided — a second approval arriving for the same item is
either a duplicate submission or a race, and silently accepting it would make the
audit trail lie about who authorized what.

Approving a recommendation records a decision. It does **not** execute anything:
there is no dispatcher here, and the stored row carries no field one could read a
command out of.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.db.orm.reporting import Recommendation
from backend.db.repositories.reporting import RecommendationRepository
from config.logging import get_logger
from models.enums import ApprovalStatus

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.orm import Session

    from models.remediation import RemediationPlan, RemediationRecommendation

_logger = get_logger(__name__)

# The statuses a human decision may set. ``PENDING`` is absent on purpose:
# un-deciding is not a decision, it is a loss of the record.
_DECIDABLE = frozenset({ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EDITED})


def to_recommendation(
    investigation_id: UUID, item: RemediationRecommendation, *, version: int = 1
) -> Recommendation:
    """Map one recommendation onto its persistent row.

    The steps and verification are folded into the rationale rather than stored
    as a separate structured field, so nothing in the database resembles a task
    list a runner could iterate. What is stored is guidance to read.
    """
    return Recommendation(
        investigation_id=investigation_id,
        action=item.action,
        type=item.type,
        priority=item.priority,
        rationale=_rationale(item),
        expected_impact=item.expected_impact,
        citations=[citation.model_dump(mode="json") for citation in item.citations],
        approval_status=ApprovalStatus.PENDING,
        requires_human_approval=True,
        version=version,
    )


def record_remediation_plan(
    session: Session, investigation_id: UUID, plan: RemediationPlan
) -> list[Recommendation]:
    """Persist a plan generation, every item pending a human decision."""
    repository = RecommendationRepository(session)
    version = repository.latest_version(investigation_id) + 1

    rows = [
        to_recommendation(investigation_id, item, version=version) for item in plan.recommendations
    ]
    if rows:
        repository.add_many(rows)

    _logger.info(
        "remediation_plan_recorded",
        investigation_id=str(investigation_id),
        version=version,
        recommendations=len(rows),
        knowledge_limited=plan.knowledge_limited,
    )
    return rows


def decide_recommendation(
    session: Session,
    recommendation_id: UUID,
    *,
    decision: ApprovalStatus,
    actor_id: str,
) -> Recommendation:
    """Record a human decision on one recommendation.

    Records a decision and nothing else. Approval means a person authorized the
    work, not that the work happened — there is deliberately no execution path
    reachable from here (invariant #2).
    """
    if decision not in _DECIDABLE:
        raise ValueError(
            f"{decision.value!r} is not a decision a human can record; "
            f"expected one of {sorted(item.value for item in _DECIDABLE)}"
        )
    if not actor_id.strip():
        raise ValueError("a recommendation decision must record who made it")

    row = session.get(Recommendation, recommendation_id)
    if row is None:
        raise ValueError(f"no recommendation {recommendation_id}")
    if row.approval_status is not ApprovalStatus.PENDING:
        raise ValueError(
            f"recommendation {recommendation_id} was already "
            f"{row.approval_status.value}; re-deciding would overwrite who authorized it"
        )

    row.approval_status = decision
    session.flush()

    _logger.info(
        "remediation_decision_recorded",
        investigation_id=str(row.investigation_id),
        recommendation_id=str(recommendation_id),
        decision=decision.value,
        actor_id=actor_id,
        executed=False,
    )
    return row


def _rationale(item: RemediationRecommendation) -> str:
    """The stored explanation: why, how, and how to confirm it worked."""
    parts = [item.rationale.strip()]
    if item.steps:
        parts.append(
            "Suggested steps for an analyst: "
            + " ".join(f"({index}) {step}" for index, step in enumerate(item.steps, start=1))
        )
    if item.verification:
        parts.append(f"Verification: {item.verification}")
    if item.targets:
        parts.append(f"Affected: {', '.join(item.targets)}.")
    parts.append(f"Grounding: {item.grounding.value.replace('_', ' ')}.")
    return " ".join(part for part in parts if part)

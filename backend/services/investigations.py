"""Investigation lifecycle and the read projections the dashboard renders.

This module is the seam between the graph and the screen. The graph *produces*;
this writes, and this reads back (invariant #7). Nothing in ``frontend/`` talks to
the graph, and nothing in ``graph/`` talks to the database.

Three decisions shape it.

**Progress is recorded, not inferred.** Each stage's completion is written onto
the investigation row as the run proceeds. Inferring it from artifacts instead
would misreport every honest empty result — a dossier that found no applicable
CVEs is indistinguishable from research that never ran — and a progress bar that
lies about what was checked is worse than none.

**The projections state their own gaps.** ``researched`` is separate from a
finding count; ``enriched`` travels with every indicator; a pipeline stage that
was deliberately skipped says so. A screen can only show a caveat the API carried.

**A recorded decision and its consequence are two steps.** The decision is
written first and stands on its own; resuming the graph is what follows from it.
If the resume fails, the record of what a person decided still exists, which is
the half that an audit needs (invariant #1).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import ColumnElement, func, select

from backend.api.schemas.investigations import (
    CreateInvestigationRequest,
    InvestigationDetail,
    InvestigationPage,
    InvestigationSnapshot,
    InvestigationSummary,
    PendingApproval,
    PendingApprovalsResponse,
    PipelineStage,
)
from backend.db.orm.analysis import CveFinding, ThreatAssessment
from backend.db.orm.conversation import Conversation, HumanDecision
from backend.db.orm.evidence import LogEvent
from backend.db.orm.investigation import Investigation
from backend.db.orm.reporting import Recommendation
from backend.db.repositories.analysis import CveFindingRepository, ThreatAssessmentRepository
from backend.db.repositories.reporting import RecommendationRepository, ReportRepository
from backend.services.report import finalize_report
from config.logging import get_logger
from graph.nodes import CVE_RESEARCH, LOG_ANALYSIS, REMEDIATION, REPORT, THREAT_DETECTION
from models.enums import (
    ApprovalStatus,
    DecisionType,
    InvestigationStatus,
    ReportStatus,
    Severity,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.orm import Session

_logger = get_logger(__name__)

# The agent stages, in pipeline order, with the label a person reads. Names come
# from the graph so the two cannot drift apart.
STAGES: tuple[tuple[str, str], ...] = (
    (LOG_ANALYSIS, "Log analysis"),
    (THREAT_DETECTION, "Threat detection"),
    (CVE_RESEARCH, "CVE research"),
    (REPORT, "Incident report"),
    (REMEDIATION, "Remediation plan"),
)

STAGE_COMPLETE = "complete"
STAGE_SKIPPED = "skipped"
STAGE_FAILED = "failed"

# Which gate decisions accept the investigation's output. ``EDIT`` is absent on
# purpose: an analyst asking for changes has not signed off on the document in
# front of them, so it stays a draft.
_ACCEPTING_DECISIONS = frozenset({DecisionType.APPROVE})


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --- Lifecycle --------------------------------------------------------------


def create_investigation(
    session: Session, *, request: CreateInvestigationRequest, actor_id: UUID | None
) -> Investigation:
    """Open an investigation over collected evidence.

    The estate context the agents assess against — which networks are internal,
    which hosts are critical — is pinned into ``config_snapshot`` at creation, so
    a replay is judged against the estate as it was rather than as it later
    became (SAD §4).
    """
    row = Investigation(
        trigger_source=request.trigger_source,
        status=InvestigationStatus.OPEN,
        title=request.title or f"{request.trigger_source.value.replace('_', ' ')}-triggered case",
        owner_id=actor_id,
        config_snapshot={
            "critical_assets": list(request.critical_assets),
            "internal_networks": list(request.internal_networks),
        },
        pipeline={},
    )
    session.add(row)
    session.flush()
    _logger.info(
        "investigation_created",
        investigation_id=str(row.id),
        trigger_source=request.trigger_source.value,
        raw_records=len(request.evidence.raw_records),
        assets=len(request.assets),
    )
    return row


def record_stage(
    session: Session,
    investigation_id: UUID,
    stage: str,
    *,
    status: str = STAGE_COMPLETE,
    detail: str = "",
) -> None:
    """Record that a pipeline stage reached ``status``.

    Re-assigning the mapping rather than mutating it in place is deliberate:
    SQLAlchemy does not track in-place edits of a JSON column, so a mutated dict
    silently never reaches the database.
    """
    row = session.get(Investigation, investigation_id)
    if row is None:
        return
    row.pipeline = {
        **row.pipeline,
        stage: {"status": status, "detail": detail, "at": _utcnow().isoformat()},
    }
    session.flush()


def mark_status(
    session: Session, investigation_id: UUID, status: InvestigationStatus
) -> Investigation | None:
    """Move an investigation's lifecycle status, stamping closure when it closes."""
    row = session.get(Investigation, investigation_id)
    if row is None:
        return None
    row.status = status
    if status is InvestigationStatus.CLOSED and row.closed_at is None:
        row.closed_at = _utcnow()
    session.flush()
    return row


def set_headline(
    session: Session, investigation_id: UUID, *, severity: Severity | None = None, summary: str = ""
) -> None:
    """Carry the assessment's headline onto the case record.

    The queue has to be sortable by how bad something is without opening every
    case, which means severity lives on the investigation row too — denormalized
    from the assessment on purpose.
    """
    row = session.get(Investigation, investigation_id)
    if row is None:
        return
    if severity is not None:
        row.severity = severity
    if summary:
        row.summary = summary
    session.flush()


# --- Human decisions --------------------------------------------------------


def record_gate_decision(
    session: Session,
    investigation_id: UUID,
    *,
    actor_id: UUID,
    decision: DecisionType,
    rationale: str | None = None,
    target: str | None = None,
) -> HumanDecision:
    """Write the human decision taken at the approval gate.

    Written before the graph is resumed, and independently of whether the resume
    succeeds. What a person decided is a fact about the past; whether the machine
    managed to act on it afterwards is a separate fact, and conflating the two
    would let an infrastructure failure erase an accountability record.
    """
    conversation = _conversation_for(session, investigation_id)
    row = HumanDecision(
        conversation_id=conversation.id,
        user_id=actor_id,
        decision=decision,
        target=target,
        rationale=rationale,
    )
    session.add(row)
    session.flush()
    _logger.info(
        "gate_decision_recorded",
        investigation_id=str(investigation_id),
        decision=decision.value,
        actor_id=str(actor_id),
        executed=False,
    )
    return row


def apply_gate_outcome(
    session: Session,
    investigation_id: UUID,
    *,
    decision: DecisionType,
    awaiting_human: bool,
) -> Investigation | None:
    """Reconcile the case record with where the graph came to rest.

    An accepted investigation also promotes its report from draft to final —
    the one transition invariant #1 reserves for a person, and the reason
    :func:`finalize_report` is a separate call rather than part of writing.
    """
    status = InvestigationStatus.AWAITING_APPROVAL if awaiting_human else InvestigationStatus.CLOSED
    row = mark_status(session, investigation_id, status)
    if decision in _ACCEPTING_DECISIONS and _has_report(session, investigation_id):
        finalize_report(session, investigation_id)
    return row


def _conversation_for(session: Session, investigation_id: UUID) -> Conversation:
    """Return the investigation's decision thread, opening one on first use."""
    stmt = select(Conversation).where(Conversation.investigation_id == investigation_id).limit(1)
    existing = session.execute(stmt).scalars().first()
    if existing is not None:
        return existing
    conversation = Conversation(investigation_id=investigation_id)
    session.add(conversation)
    session.flush()
    return conversation


def _has_report(session: Session, investigation_id: UUID) -> bool:
    return ReportRepository(session).current(investigation_id) is not None


# --- Read projections -------------------------------------------------------


def snapshot_of(session: Session, investigation: Investigation) -> InvestigationSnapshot:
    """Build the live control view of one investigation."""
    assessment = ThreatAssessmentRepository(session).current(investigation.id)
    report = ReportRepository(session).current(investigation.id)
    recommendations = RecommendationRepository(session).current(investigation.id)
    pending = [item for item in recommendations if item.approval_status is ApprovalStatus.PENDING]

    return InvestigationSnapshot(
        id=investigation.id,
        status=investigation.status,
        severity=investigation.severity,
        verdict=assessment.verdict if assessment else None,
        triage_priority=assessment.triage_priority if assessment else None,
        confidence=assessment.confidence if assessment else None,
        awaiting_human=investigation.status is InvestigationStatus.AWAITING_APPROVAL,
        pipeline=pipeline_of(investigation),
        event_count=_count(session, LogEvent, investigation.id),
        cve_count=_count(session, CveFinding, investigation.id),
        recommendation_count=len(recommendations),
        pending_approvals=len(pending),
        report_version=report.version if report else 0,
        updated_at=investigation.updated_at,
    )


def pipeline_of(investigation: Investigation) -> list[PipelineStage]:
    """Project the recorded stage log into the ordered view a screen renders.

    A stage with no record is simply not complete. That is the correct reading
    for a run in progress and for a run that died: the record says what happened,
    and silence is not evidence that something succeeded.
    """
    recorded = investigation.pipeline or {}
    stages: list[PipelineStage] = []
    for name, label in STAGES:
        entry = recorded.get(name) or {}
        status = str(entry.get("status", ""))
        stages.append(
            PipelineStage(
                name=name,
                label=label,
                complete=status == STAGE_COMPLETE,
                skipped=status == STAGE_SKIPPED,
                detail=str(entry.get("detail")) or None,
            )
        )
    return stages


def detail_of(session: Session, investigation: Investigation) -> InvestigationDetail:
    """Build the investigation workspace header."""
    return InvestigationDetail(
        id=investigation.id,
        title=investigation.title,
        summary=investigation.summary,
        status=investigation.status,
        severity=investigation.severity,
        trigger_source=investigation.trigger_source,
        owner_id=investigation.owner_id,
        snapshot=snapshot_of(session, investigation),
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
        closed_at=investigation.closed_at,
    )


def summary_of(session: Session, investigation: Investigation) -> InvestigationSummary:
    """Build one dashboard queue row."""
    assessment = ThreatAssessmentRepository(session).current(investigation.id)
    pending = RecommendationRepository(session).pending_approval(investigation.id)
    return InvestigationSummary(
        id=investigation.id,
        title=investigation.title,
        status=investigation.status,
        severity=investigation.severity,
        trigger_source=investigation.trigger_source,
        verdict=assessment.verdict if assessment else None,
        triage_priority=assessment.triage_priority if assessment else None,
        confidence=assessment.confidence if assessment else None,
        pending_approvals=len(pending),
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
        closed_at=investigation.closed_at,
    )


def list_investigations(
    session: Session,
    *,
    limit: int,
    offset: int,
    status: InvestigationStatus | None = None,
    severity: Severity | None = None,
    owner_id: UUID | None = None,
) -> InvestigationPage:
    """A page of investigations, newest first.

    ``total`` is counted under the same filters rather than over the whole table,
    because a queue that says "12 of 4,000" when 12 match is telling an analyst
    the wrong thing about their backlog.
    """
    conditions: list[ColumnElement[bool]] = [Investigation.deleted_at.is_(None)]
    if status is not None:
        conditions.append(Investigation.status == status)
    if severity is not None:
        conditions.append(Investigation.severity == severity)
    if owner_id is not None:
        conditions.append(Investigation.owner_id == owner_id)

    total = session.execute(
        select(func.count()).select_from(Investigation).where(*conditions)
    ).scalar_one()
    rows = (
        session.execute(
            select(Investigation)
            .where(*conditions)
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return InvestigationPage(
        items=[summary_of(session, row) for row in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


def pending_approvals_of(
    session: Session, investigation: Investigation
) -> PendingApprovalsResponse:
    """Everything on this investigation that is waiting on a person.

    The open gate is reported separately from the item list. An investigation can
    be paused at the gate with nothing to remediate, and a screen driven only by
    the item count would render that as "nothing to do" while the pipeline sits
    stopped waiting for exactly this person.
    """
    assessment = ThreatAssessmentRepository(session).current(investigation.id)
    items: list[PendingApproval] = [
        PendingApproval(
            kind="recommendation",
            id=item.id,
            investigation_id=investigation.id,
            title=item.action,
            priority=item.priority,
            rationale=item.rationale,
        )
        for item in RecommendationRepository(session).pending_approval(investigation.id)
    ]
    report = ReportRepository(session).current(investigation.id)
    if report is not None and report.status is ReportStatus.DRAFT:
        items.insert(
            0,
            PendingApproval(
                kind="report",
                id=report.id,
                investigation_id=investigation.id,
                title=f"Incident report v{report.version}",
                confidence=assessment.confidence if assessment else None,
                rationale=report.executive_summary,
            ),
        )
    return PendingApprovalsResponse(
        investigation_id=investigation.id,
        gate_open=investigation.status is InvestigationStatus.AWAITING_APPROVAL,
        items=items,
    )


def cve_research_ran(session: Session, investigation: Investigation) -> bool:
    """Whether vulnerability research actually executed for this investigation.

    Read from the recorded stage log rather than from the finding count, because
    "we researched and nothing applied" and "we never researched" are different
    statements about an estate, and only one of them means an analyst can stop
    looking.
    """
    entry = (investigation.pipeline or {}).get(CVE_RESEARCH) or {}
    return str(entry.get("status", "")) == STAGE_COMPLETE


def dossier_version(session: Session, investigation_id: UUID) -> int:
    """The current CVE dossier generation, or ``0`` when none was written."""
    return CveFindingRepository(session).latest_version(investigation_id)


def _count(session: Session, model: Any, investigation_id: UUID) -> int:
    """Count one investigation's rows in a child table.

    ``model`` is loosely typed because the three tables counted here share the
    ``investigation_id`` column but no common base that declares it.
    """
    stmt = select(func.count()).select_from(model).where(model.investigation_id == investigation_id)
    return int(session.execute(stmt).scalar_one())


def latest_assessment(session: Session, investigation_id: UUID) -> ThreatAssessment | None:
    """The current threat assessment, or ``None`` if detection has not run."""
    return ThreatAssessmentRepository(session).current(investigation_id)


def current_recommendations(session: Session, investigation_id: UUID) -> list[Recommendation]:
    """The current remediation plan generation."""
    return RecommendationRepository(session).current(investigation_id)

"""Investigation endpoints: trigger, read, stream, and decide.

Command/query separation (SAD §12). Triggering an investigation returns a handle
and the work proceeds in the background; everything else reads what the backend
persisted, and the human gate is a first-class endpoint rather than a side effect
of some other call.

Every route is capability-guarded and every mutation is audited. The two decision
endpoints are the only ones that change an approval state, and neither of them
executes anything — approving records that a person authorized work, which is a
different fact from the work having happened (invariant #2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.api.deps import (
    get_db,
    get_db_session_factory,
    get_graph_runtime,
    get_settings_dep,
    require_capability,
)
from backend.api.errors import ConflictError, NotFoundError
from backend.api.schemas.investigations import (
    CreateInvestigationRequest,
    CveFindingsResponse,
    CveFindingView,
    GateDecisionRequest,
    GateDecisionResponse,
    InvestigationDetail,
    InvestigationPage,
    InvestigationSummary,
    PendingApprovalsResponse,
    RecommendationDecisionRequest,
    RecommendationsResponse,
    RecommendationView,
    ReportHistoryResponse,
    ReportVersionRef,
    ReportView,
    ThreatAssessmentView,
    ThreatIndicator,
    ThreatTechnique,
    TimelineEvent,
    TimelineResponse,
)
from backend.api.stream import investigation_events
from backend.auth.rbac import Capability
from backend.auth.schemas import Principal
from backend.db.orm.investigation import Investigation
from backend.db.orm.reporting import Recommendation
from backend.db.repositories.analysis import CveFindingRepository
from backend.db.repositories.audit import AuditLogRepository
from backend.db.repositories.evidence import LogEventRepository
from backend.db.repositories.reporting import ReportRepository
from backend.services import investigations as service
from backend.services.remediation import decide_recommendation
from backend.workers.investigations import run_investigation
from config.settings import Settings
from models.enums import InvestigationStatus, Severity
from models.values import Citation

if TYPE_CHECKING:
    from collections.abc import Callable

    from graph.runtime import InvestigationGraphService

router = APIRouter(prefix="/investigations", tags=["investigations"])

# How many timeline events one response may carry. Beyond this the client is
# told the view is truncated rather than handed a silently partial history.
TIMELINE_LIMIT = 500

_view = Depends(require_capability(Capability.VIEW_INVESTIGATIONS))
_run = Depends(require_capability(Capability.RUN_INVESTIGATIONS))
_approve = Depends(require_capability(Capability.APPROVE_ACTIONS))


def _load(session: Session, investigation_id: UUID) -> Investigation:
    """Load a live investigation or refuse the request.

    A soft-deleted case is reported as absent rather than as forbidden: the
    distinction leaks whether an id ever existed, and nothing on this screen
    needs it.
    """
    row = session.get(Investigation, investigation_id)
    if row is None or row.deleted_at is not None:
        raise NotFoundError("no such investigation")
    return row


# --- Commands ---------------------------------------------------------------


@router.post("", response_model=InvestigationSummary, status_code=202)
def create_investigation(
    body: CreateInvestigationRequest,
    background: BackgroundTasks,
    request: Request,
    principal: Principal = _run,
    db: Session = Depends(get_db),
    graph: InvestigationGraphService = Depends(get_graph_runtime),
    session_factory: Callable[[], Session] = Depends(get_db_session_factory),
) -> InvestigationSummary:
    """Trigger an investigation and return its handle immediately.

    202 rather than 201: the case record exists, but the analysis it will carry
    does not yet. The client subscribes to the stream and watches it arrive.
    """
    row = service.create_investigation(db, request=body, actor_id=principal.user_id)
    AuditLogRepository(db).append(
        action="investigation.created",
        entity_type="investigation",
        entity_id=row.id,
        actor_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
    # Committed before the run is scheduled, not left to the request teardown.
    # The background run opens its own sessions and writes rows that reference
    # this one; if the case record were still uncommitted when it started, every
    # one of those writes would fail a foreign key against a row that exists only
    # inside a transaction nobody else can see.
    db.commit()
    background.add_task(
        run_investigation,
        session_factory,
        graph,
        investigation_id=row.id,
        request=body,
    )
    return service.summary_of(db, row)


@router.post("/{investigation_id}/decision", response_model=GateDecisionResponse)
def decide(
    investigation_id: UUID,
    body: GateDecisionRequest,
    request: Request,
    principal: Principal = _approve,
    db: Session = Depends(get_db),
    graph: InvestigationGraphService = Depends(get_graph_runtime),
) -> GateDecisionResponse:
    """Record a human decision at the approval gate and resume the investigation.

    The decision is written and committed *before* the graph is resumed. What a
    person decided is a fact regardless of whether the machine then managed to
    act on it, and an orchestration failure must not be able to erase an
    accountability record (invariant #1).
    """
    row = _load(db, investigation_id)
    if row.status is not InvestigationStatus.AWAITING_APPROVAL:
        raise ConflictError(
            f"investigation is {row.status.value}; there is no open approval gate to decide"
        )

    decision = service.record_gate_decision(
        db,
        investigation_id,
        actor_id=principal.user_id,
        decision=body.decision,
        rationale=body.rationale,
        target=body.target,
    )
    AuditLogRepository(db).append(
        action=f"investigation.decision.{body.decision.value}",
        entity_type="investigation",
        entity_id=investigation_id,
        actor_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    result = graph.resume(investigation_id=str(investigation_id), decision=body.decision.value)
    service.apply_gate_outcome(
        db, investigation_id, decision=body.decision, awaiting_human=result.awaiting_human
    )
    updated = _load(db, investigation_id)
    return GateDecisionResponse(
        investigation_id=investigation_id,
        decision=body.decision,
        status=updated.status,
        awaiting_human=result.awaiting_human,
        recorded_at=decision.created_at,
    )


@router.post(
    "/{investigation_id}/recommendations/{recommendation_id}/decision",
    response_model=RecommendationView,
)
def decide_on_recommendation(
    investigation_id: UUID,
    recommendation_id: UUID,
    body: RecommendationDecisionRequest,
    request: Request,
    principal: Principal = _approve,
    db: Session = Depends(get_db),
) -> RecommendationView:
    """Record a human decision on one remediation recommendation."""
    _load(db, investigation_id)
    existing = db.get(Recommendation, recommendation_id)
    if existing is None or existing.investigation_id != investigation_id:
        raise NotFoundError("no such recommendation on this investigation")

    try:
        decided = decide_recommendation(
            db,
            recommendation_id,
            decision=body.decision,
            actor_id=str(principal.user_id),
        )
    except ValueError as exc:
        raise ConflictError(str(exc)) from exc

    AuditLogRepository(db).append(
        action=f"recommendation.decision.{body.decision.value}",
        entity_type="recommendation",
        entity_id=recommendation_id,
        actor_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
    return _recommendation_view(decided)


# --- Queries ----------------------------------------------------------------


@router.get("", response_model=InvestigationPage)
def list_investigations(
    principal: Principal = _view,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    status: InvestigationStatus | None = None,
    severity: Severity | None = None,
    mine: bool = False,
    limit: int | None = Query(default=None, ge=1),
    offset: int = Query(default=0, ge=0),
) -> InvestigationPage:
    """The dashboard queue, newest first.

    ``mine`` scopes to the caller's own cases — the "awaiting *my* attention"
    view — without inventing an assignment model the domain does not have.
    """
    size = min(limit or settings.investigation_page_size, settings.investigation_page_size_max)
    return service.list_investigations(
        db,
        limit=size,
        offset=offset,
        status=status,
        severity=severity,
        owner_id=principal.user_id if mine else None,
    )


@router.get("/{investigation_id}", response_model=InvestigationDetail)
def get_investigation(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> InvestigationDetail:
    """The investigation workspace header, including live pipeline progress."""
    return service.detail_of(db, _load(db, investigation_id))


@router.get("/{investigation_id}/timeline", response_model=TimelineResponse)
def get_timeline(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> TimelineResponse:
    """The chronological reconstruction, with each event's provenance."""
    _load(db, investigation_id)
    rows = LogEventRepository(db).for_investigation(investigation_id, limit=TIMELINE_LIMIT)
    return TimelineResponse(
        investigation_id=investigation_id,
        events=[
            TimelineEvent(
                id=row.id,
                event_time=row.event_time,
                source=row.source,
                event_type=row.event_type,
                actor=row.actor,
                notability=row.notability,
                raw_ref=row.raw_ref,
                provenance=row.provenance,
            )
            for row in rows
        ],
        truncated=len(rows) >= TIMELINE_LIMIT,
    )


@router.get("/{investigation_id}/threat", response_model=ThreatAssessmentView)
def get_threat(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> ThreatAssessmentView:
    """The current threat assessment."""
    _load(db, investigation_id)
    row = service.latest_assessment(db, investigation_id)
    if row is None:
        raise NotFoundError("threat detection has not produced an assessment yet")
    return ThreatAssessmentView(
        id=row.id,
        investigation_id=row.investigation_id,
        verdict=row.verdict,
        severity=row.severity,
        triage_priority=row.triage_priority,
        enrichment_status=row.enrichment_status,
        confidence=row.confidence,
        rationale=row.rationale,
        indicators=[ThreatIndicator.model_validate(item) for item in row.iocs],
        techniques=[ThreatTechnique.model_validate(item) for item in row.attack_techniques],
        version=row.version,
        created_at=row.created_at,
    )


@router.get("/{investigation_id}/cves", response_model=CveFindingsResponse)
def get_cves(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> CveFindingsResponse:
    """The current dossier generation — confirmations and candidates together."""
    row = _load(db, investigation_id)
    findings = CveFindingRepository(db).current(investigation_id)
    return CveFindingsResponse(
        investigation_id=investigation_id,
        researched=service.cve_research_ran(db, row),
        findings=[
            CveFindingView(
                id=finding.id,
                cve_id=finding.cve_id,
                applicability=finding.applicability,
                summary=finding.summary,
                cvss=finding.cvss,
                exploit_mapping=finding.exploit_mapping,
                citations=_citations(finding.citations),
                source_freshness=finding.source_freshness,
                version=finding.version,
            )
            for finding in findings
        ],
        version=service.dossier_version(db, investigation_id),
    )


@router.get("/{investigation_id}/report", response_model=ReportView)
def get_report(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
    version: int | None = Query(default=None, ge=1),
) -> ReportView:
    """A generated report — the current one, or a named earlier version."""
    _load(db, investigation_id)
    repository = ReportRepository(db)
    row = (
        repository.for_version(investigation_id, version)
        if version is not None
        else repository.current(investigation_id)
    )
    if row is None:
        raise NotFoundError("no report has been generated for this investigation")
    return ReportView(
        id=row.id,
        investigation_id=row.investigation_id,
        executive_summary=row.executive_summary,
        technical_body=row.technical_body,
        citations=_citations(row.citations),
        status=row.status,
        version=row.version,
        created_at=row.created_at,
    )


@router.get("/{investigation_id}/report/history", response_model=ReportHistoryResponse)
def get_report_history(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> ReportHistoryResponse:
    """Every generation, so the document a decision rested on stays reachable."""
    _load(db, investigation_id)
    return ReportHistoryResponse(
        investigation_id=investigation_id,
        versions=[
            ReportVersionRef(
                id=row.id, version=row.version, status=row.status, created_at=row.created_at
            )
            for row in ReportRepository(db).history(investigation_id)
        ],
    )


@router.get("/{investigation_id}/recommendations", response_model=RecommendationsResponse)
def get_recommendations(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> RecommendationsResponse:
    """The current remediation plan generation, most urgent first."""
    _load(db, investigation_id)
    rows = service.current_recommendations(db, investigation_id)
    return RecommendationsResponse(
        investigation_id=investigation_id,
        recommendations=[_recommendation_view(row) for row in rows],
        version=rows[0].version if rows else 0,
    )


@router.get("/{investigation_id}/pending-approvals", response_model=PendingApprovalsResponse)
def get_pending_approvals(
    investigation_id: UUID,
    principal: Principal = _view,
    db: Session = Depends(get_db),
) -> PendingApprovalsResponse:
    """Everything on this investigation that is waiting on a person."""
    return service.pending_approvals_of(db, _load(db, investigation_id))


@router.get("/{investigation_id}/stream")
def stream_investigation(
    investigation_id: UUID,
    request: Request,
    principal: Principal = _view,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    session_factory: Callable[[], Session] = Depends(get_db_session_factory),
) -> StreamingResponse:
    """Subscribe to live progress for one investigation.

    Existence is checked here, before the response begins, so a missing
    investigation is an honest 404 rather than a 200 carrying an error frame the
    client has to parse to discover the request failed.
    """
    _load(db, investigation_id)
    return StreamingResponse(
        investigation_events(request, session_factory, investigation_id, settings=settings),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            # Tells reverse proxies not to buffer, which would otherwise hold
            # events until the response ends — i.e. defeat the stream entirely.
            "X-Accel-Buffering": "no",
        },
    )


# --- Projection helpers -----------------------------------------------------


def _recommendation_view(row: Recommendation) -> RecommendationView:
    return RecommendationView(
        id=row.id,
        investigation_id=row.investigation_id,
        action=row.action,
        type=row.type,
        priority=row.priority,
        rationale=row.rationale,
        expected_impact=row.expected_impact,
        citations=_citations(row.citations),
        approval_status=row.approval_status,
        requires_human_approval=row.requires_human_approval,
        version=row.version,
        created_at=row.created_at,
    )


def _citations(stored: list[dict[str, Any]]) -> list[Citation]:
    """Stored citations, dropping any that no longer satisfy the contract.

    A citation that cannot be read is dropped rather than rendered half-formed:
    a reference an analyst cannot follow is worse than a visibly missing one,
    because it looks like support.
    """
    citations: list[Citation] = []
    for item in stored:
        try:
            citations.append(Citation.model_validate(item))
        except ValueError:
            continue
    return citations

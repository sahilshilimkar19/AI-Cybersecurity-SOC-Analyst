"""Runs an investigation and persists each agent's output as it lands.

An investigation is long work, so the API starts it and returns a handle rather
than holding a request open for its duration (SAD §12). This is what runs behind
that handle.

The persistence is **incremental on purpose**. Each agent's output is written the
moment that agent finishes, in its own transaction, which buys two things. The
dashboard has something true to show while the pipeline is still running — a
stream over a run that only writes at the end has nothing to stream. And a run
that dies at the fourth stage leaves the first three stages' work in the record
instead of discarding an investigation's worth of analysis (invariant #6).

Nothing here decides anything. It moves what the graph produced into the tables
the backend owns, and records what ran. The one status it may set on its own is
"awaiting approval", which is a request for a human, not a disposition.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from backend.api.schemas.investigations import CreateInvestigationRequest
from backend.services.assessment import record_threat_assessment
from backend.services.evidence import record_log_events
from backend.services.investigations import (
    STAGE_COMPLETE,
    STAGE_FAILED,
    STAGE_SKIPPED,
    mark_status,
    record_stage,
    set_headline,
)
from backend.services.remediation import record_remediation_plan
from backend.services.report import record_report_content
from backend.services.vulnerability import record_cve_findings
from config.logging import get_logger
from graph.nodes import (
    CLOSE,
    CVE_RESEARCH,
    LOG_ANALYSIS,
    REMEDIATION,
    REPORT,
    THREAT_DETECTION,
    TRIAGE,
)
from models.enums import InvestigationStatus, Verdict
from models.logs import NormalizedEvent
from models.remediation import RemediationPlan
from models.threat import ThreatDetectionResult
from models.vulnerability import CveResearchResult

if TYPE_CHECKING:
    from uuid import UUID

    from graph.runtime import InvestigationGraphService

SessionFactory = Callable[[], Session]

_logger = get_logger(__name__)


def run_investigation(
    session_factory: SessionFactory,
    graph: InvestigationGraphService,
    *,
    investigation_id: UUID,
    request: CreateInvestigationRequest,
) -> None:
    """Execute an investigation end-to-end, persisting each stage as it completes."""
    thread_id = str(investigation_id)
    _write(
        session_factory, lambda s: mark_status(s, investigation_id, InvestigationStatus.IN_PROGRESS)
    )

    def on_node(node: str, update: dict[str, Any]) -> None:
        _write(session_factory, lambda s: _persist(s, investigation_id, node, update))

    try:
        result = graph.start(
            investigation_id=thread_id,
            trigger_source=request.trigger_source.value,
            config_snapshot={
                "critical_assets": list(request.critical_assets),
                "internal_networks": list(request.internal_networks),
            },
            evidence=request.evidence.model_dump(mode="json"),
            assets=[asset.model_dump(mode="json") for asset in request.assets],
            on_node=on_node,
        )
    except Exception as exc:
        # A failed run is recorded, never swallowed: the stage it died at is
        # written onto the case so the screen shows where the pipeline stopped
        # rather than an investigation that simply never finishes (invariant #6).
        reason = type(exc).__name__
        _logger.error(
            "investigation_run_failed", investigation_id=thread_id, error=str(exc), exc_info=True
        )
        _write(
            session_factory,
            lambda s: record_stage(
                s,
                investigation_id,
                _failed_stage(s, investigation_id),
                status=STAGE_FAILED,
                detail=reason,
            ),
        )
        return

    _logger.info(
        "investigation_run_finished",
        investigation_id=thread_id,
        status=result.status,
        awaiting_human=result.awaiting_human,
    )


def _persist(session: Session, investigation_id: UUID, node: str, update: dict[str, Any]) -> None:
    """Move one node's output into the tables the backend owns."""
    findings = update.get("investigation") or {}

    if node == LOG_ANALYSIS:
        events, unreadable = _normalized_events(findings.get("normalized_events", []))
        written = record_log_events(session, investigation_id, events)
        detail = f"{written} event(s)"
        if unreadable:
            detail += f", {unreadable} unreadable"
        record_stage(session, investigation_id, LOG_ANALYSIS, detail=detail)

    elif node == THREAT_DETECTION:
        assessment = ThreatDetectionResult.model_validate(findings["threat_assessment"])
        record_threat_assessment(session, investigation_id, assessment)
        set_headline(session, investigation_id, severity=assessment.severity.level)
        record_stage(
            session,
            investigation_id,
            THREAT_DETECTION,
            detail=f"{assessment.verdict.value}, {assessment.severity.level.value}",
        )
        # Recorded here rather than left blank: a benign verdict means research
        # was correctly not performed, and an unmarked stage reads as one that is
        # still pending or that quietly failed.
        if assessment.verdict is Verdict.BENIGN:
            record_stage(
                session,
                investigation_id,
                CVE_RESEARCH,
                status=STAGE_SKIPPED,
                detail="benign verdict; vulnerability research not required",
            )

    elif node == CVE_RESEARCH:
        dossier = CveResearchResult.model_validate(findings["vulnerability_dossier"])
        record_cve_findings(session, investigation_id, dossier)
        detail = f"{len(dossier.cves)} confirmed, {len(dossier.candidates)} candidate(s)"
        if dossier.stale:
            detail += "; assembled from the indexed corpus"
        record_stage(session, investigation_id, CVE_RESEARCH, detail=detail)

    elif node == REPORT:
        report = update.get("report") or {}
        row = record_report_content(
            session,
            investigation_id,
            executive_summary=str(report.get("executive_summary") or ""),
            technical_body=str(report.get("technical_report") or ""),
            citations=list(report.get("citations") or []),
        )
        set_headline(session, investigation_id, summary=row.executive_summary)
        record_stage(
            session,
            investigation_id,
            REPORT,
            detail=f"v{row.version}, {len(row.citations)} citation(s)",
        )

    elif node == REMEDIATION:
        plan = RemediationPlan.model_validate(findings["remediation_plan"])
        rows = record_remediation_plan(session, investigation_id, plan)
        record_stage(
            session,
            investigation_id,
            REMEDIATION,
            detail=f"{len(rows)} recommendation(s), all pending approval",
        )

    elif node == TRIAGE:
        mark_status(session, investigation_id, InvestigationStatus.AWAITING_APPROVAL)

    elif node == CLOSE:
        mark_status(session, investigation_id, InvestigationStatus.CLOSED)


def _normalized_events(payload: list[Any]) -> tuple[list[NormalizedEvent], int]:
    """Validate the events the analyzer produced, counting rather than raising.

    One unreadable record must not cost the whole timeline; the count becomes
    part of the stage detail so the shortfall is visible on the screen instead of
    only in a log nobody is reading.
    """
    events: list[NormalizedEvent] = []
    unreadable = 0
    for item in payload:
        try:
            events.append(NormalizedEvent.model_validate(item))
        except ValueError:
            unreadable += 1
    return events, unreadable


def _failed_stage(session: Session, investigation_id: UUID) -> str:
    """The first stage with no recorded outcome — where the run stopped."""
    from backend.db.orm.investigation import Investigation

    row = session.get(Investigation, investigation_id)
    recorded = (row.pipeline if row else {}) or {}
    order = (LOG_ANALYSIS, THREAT_DETECTION, CVE_RESEARCH, REPORT, REMEDIATION)
    for stage in order:
        if str((recorded.get(stage) or {}).get("status", "")) not in {
            STAGE_COMPLETE,
            STAGE_SKIPPED,
        }:
            return stage
    return REMEDIATION


def _write(session_factory: SessionFactory, operation: Callable[[Session], Any]) -> None:
    """Run one persistence step in its own committed transaction.

    Per-step transactions are what make progress visible while the run is still
    going. They also mean a later failure cannot roll back an earlier agent's
    output, which is the behavior an analyst watching the screen needs.
    """
    session = session_factory()
    try:
        operation(session)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

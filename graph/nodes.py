"""System and stub nodes for the LangGraph Core skeleton.

These are the *deterministic control-plane* nodes only. The agent nodes (Planner,
Log Analyzer, Threat Detector, ...) are empty here and land in their own sprints;
``triage`` is the seam where that pipeline will attach. What this sprint proves is
the machinery: a stub pipeline that runs end-to-end, checkpoints every transition,
pauses at a first-class human interrupt gate, and resumes/redirects on a recorded
decision (governing invariants #1 and #5).

No agent reasoning, no model calls, no external I/O — every node is deterministic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from langgraph.types import interrupt

from graph.state import GraphState, NodeTransition
from models.enums import DecisionType, InvestigationStatus, Verdict

# Node identifiers. Kept here so routing and the registry share one source of truth.
INGEST_SEED = "ingest_seed"
LOG_ANALYSIS = "log_analysis"
THREAT_DETECTION = "threat_detection"
CVE_RESEARCH = "cve_research"
TRIAGE = "triage"
HUMAN_GATE = "human_gate"
CLOSE = "close"

# Node ownership (SAD §5): system nodes belong to the graph runtime; the approval
# gate belongs to human review; agent nodes are owned by their agent.
_OWNER_RUNTIME = "graph-runtime"
_OWNER_HUMAN = "human-review"
_OWNER_LOG_ANALYZER = "log-analyzer"
_OWNER_THREAT_DETECTOR = "threat-detector"
_OWNER_CVE_RESEARCH = "cve-research"


def _utcnow() -> str:
    """Wall-clock stamp for ``updated_at`` (monkeypatched in deterministic tests)."""
    return datetime.now(UTC).isoformat()


def _transition(node: str, owner: str, status: str, detail: str = "") -> NodeTransition:
    """Build a transition record; the reducer stamps its ``sequence``."""
    return NodeTransition(sequence=0, node=node, owner=owner, status=status, detail=detail)


def ingest_seed(state: GraphState) -> dict[str, Any]:
    """Seed the investigation from its trigger and mark it in progress."""
    return {
        "status": InvestigationStatus.IN_PROGRESS.value,
        "current_node": INGEST_SEED,
        "updated_at": _utcnow(),
        "node_history": [
            _transition(INGEST_SEED, _OWNER_RUNTIME, "completed", "investigation seeded")
        ],
    }


def log_analysis(state: GraphState) -> dict[str, Any]:
    """Normalize and correlate the seeded evidence into a timeline.

    Writes only into its own agent record and the investigation findings; the raw
    evidence it read is left untouched, so what the graph ingested stays
    distinguishable from what analysis concluded.

    A source that failed to collect arrives here as a recorded failure rather than
    an exception, and leaves as a coverage gap — the investigation proceeds with
    what is available (invariant #6).
    """
    from agents.log_analyzer import AGENT_NAME, LogAnalyzer
    from integrations.log_sources import LogFetchFailure
    from models.logs import LogAnalysisRequest, RawLogRecord, TimeWindow

    evidence = state["evidence"]
    window_payload = evidence.get("time_window")
    request = LogAnalysisRequest(
        investigation_id=state["investigation_id"],
        records=[RawLogRecord.model_validate(item) for item in evidence.get("raw_records", [])],
        requested_sources=list(evidence.get("requested_sources", [])),
        time_window=TimeWindow.model_validate(window_payload) if window_payload else None,
    )
    failures = [
        LogFetchFailure(
            source_id=str(item.get("source_id", "")),
            reason=str(item.get("reason", "unknown")),
            detail=str(item.get("detail", "")),
        )
        for item in evidence.get("source_failures", [])
    ]

    outcome = LogAnalyzer().analyze(request, source_failures=failures)
    result = outcome.output

    return {
        "current_node": LOG_ANALYSIS,
        "updated_at": _utcnow(),
        "investigation": {
            "normalized_events": [event.model_dump(mode="json") for event in result.events],
            "timeline": [entry.model_dump(mode="json") for entry in result.timeline],
            "coverage_gaps": [
                f"{gap.kind.value}: {gap.detail}".strip(": ") for gap in result.coverage_gaps
            ],
        },
        "agents": {
            AGENT_NAME: {
                "agent_name": AGENT_NAME,
                "last_output": {
                    "events": len(result.events),
                    "correlations": len(result.correlations),
                    "quarantined": len(result.quarantined),
                    "source_coverage": result.source_coverage,
                    "parse_failure_rate": result.parse_failure_rate,
                    "prompt_version": outcome.prompt_version,
                },
                "confidence": outcome.confidence,
                "retry_count": 0,
                "tool_calls": outcome.tool_calls,
            }
        },
        "node_history": [
            _transition(
                LOG_ANALYSIS,
                _OWNER_LOG_ANALYZER,
                "completed",
                f"{len(result.events)} events, {len(result.correlations)} correlations, "
                f"{len(result.coverage_gaps)} gaps",
            )
        ],
    }


def threat_detection(state: GraphState) -> dict[str, Any]:
    """Assess the normalized evidence into a verdict, IoCs, techniques, and severity.

    Reads the findings the Log Analyzer wrote and writes only the assessment and
    its own agent record — evidence stays exactly as it was ingested, so what was
    *seen* remains distinguishable from what was *concluded* about it.

    Estate context (which networks are internal, which assets are critical) comes
    from the pinned ``config_snapshot`` rather than from live configuration, so a
    replayed investigation is assessed against the same estate it originally was.
    """
    from agents.threat_detector import AGENT_NAME, ThreatDetector
    from models.threat import ThreatDetectionRequest

    findings = state["investigation"]
    snapshot = state.get("config_snapshot", {})
    request = ThreatDetectionRequest(
        investigation_id=state["investigation_id"],
        events=list(findings.get("normalized_events", [])),
        timeline=list(findings.get("timeline", [])),
        coverage_gaps=list(findings.get("coverage_gaps", [])),
        internal_networks=list(snapshot.get("internal_networks", [])),
        critical_assets=list(snapshot.get("critical_assets", [])),
    )

    outcome = ThreatDetector().assess(request)
    result = outcome.output

    return {
        "current_node": THREAT_DETECTION,
        "updated_at": _utcnow(),
        "investigation": {"threat_assessment": result.model_dump(mode="json")},
        "agents": {
            AGENT_NAME: {
                "agent_name": AGENT_NAME,
                "last_output": {
                    "verdict": result.verdict.value,
                    "severity": result.severity.level.value,
                    "severity_score": result.severity.score,
                    "triage_priority": result.triage_priority.value,
                    "signals": len(result.signals),
                    "iocs": len(result.iocs),
                    "attack_techniques": [
                        technique.technique_id for technique in result.attack_techniques
                    ],
                    "enrichment_status": result.enrichment_status.value,
                    "escalation_required": result.escalation_required,
                    "prompt_version": outcome.prompt_version,
                },
                "confidence": outcome.confidence,
                "retry_count": 0,
                "tool_calls": outcome.tool_calls,
            }
        },
        "node_history": [
            _transition(
                THREAT_DETECTION,
                _OWNER_THREAT_DETECTOR,
                "completed",
                f"verdict={result.verdict.value}, severity={result.severity.level.value}, "
                f"{len(result.signals)} signal(s), {len(result.attack_techniques)} technique(s)",
            )
        ],
    }


def cve_research(state: GraphState) -> dict[str, Any]:
    """Research the vulnerabilities relevant to an assessed threat.

    Reached only when the Threat Detector returned something other than benign
    (see :func:`route_after_threat`). Reads the assessment and the asset
    inventory, writes only the dossier and its own agent record.

    CVE identifiers named in the evidence are collected and looked up rather than
    believed: a log line can claim anything, and a scanner's assertion is a
    starting point for research, not a finding (invariant #3).
    """
    from agents.cve_research import AGENT_NAME, CveResearcher, find_cve_ids
    from models.vulnerability import AssetContext, CveResearchRequest

    findings = state["investigation"]
    assets, unreadable = _asset_contexts(state["shared"].get("assets", []), AssetContext)

    outcome = CveResearcher().research(
        CveResearchRequest(
            investigation_id=state["investigation_id"],
            threat_assessment=findings.get("threat_assessment"),
            assets=assets,
            referenced_cve_ids=find_cve_ids(
                " ".join(
                    str(event.get("message", "")) for event in findings.get("normalized_events", [])
                )
            ),
        )
    )
    result = outcome.output

    detail = (
        f"{len(result.cves)} confirmed, {len(result.candidates)} candidate(s) "
        f"across {len(result.searched_products)} product(s)"
    )
    if unreadable:
        detail += f"; {unreadable} asset record(s) unreadable"

    return {
        "current_node": CVE_RESEARCH,
        "updated_at": _utcnow(),
        "investigation": {"vulnerability_dossier": result.model_dump(mode="json")},
        "agents": {
            AGENT_NAME: {
                "agent_name": AGENT_NAME,
                "last_output": {
                    "confirmed": len(result.cves),
                    "candidates": len(result.candidates),
                    "searched_products": result.searched_products,
                    "highest_severity": (
                        result.highest_severity.value if result.highest_severity else None
                    ),
                    "stale": result.stale,
                    "prompt_version": outcome.prompt_version,
                },
                "confidence": outcome.confidence,
                "retry_count": 0,
                "tool_calls": outcome.tool_calls,
            }
        },
        "node_history": [_transition(CVE_RESEARCH, _OWNER_CVE_RESEARCH, "completed", detail)],
    }


def _asset_contexts(payload: list[dict[str, Any]], model: type[Any]) -> tuple[list[Any], int]:
    """Validate seeded asset records, counting rather than raising on bad ones.

    One malformed inventory entry must not cost the whole dossier; the count
    becomes part of the node's transition detail so the shortfall is visible.
    """
    assets: list[Any] = []
    unreadable = 0
    for item in payload:
        try:
            assets.append(model.model_validate(item))
        except ValueError:
            unreadable += 1
    return assets, unreadable


def route_after_threat(state: GraphState) -> str:
    """Branch on the verdict (SAD §5 conditional routing).

    A benign assessment skips vulnerability research and goes straight to triage:
    researching CVEs for activity nothing flagged spends real time and real API
    budget to answer a question nobody asked. Anything else — suspicious or
    malicious — earns the deeper work.

    Note what this branch is *not*: it is not a route to ``close``. Both paths
    converge on triage and then on the human gate, because closing an
    investigation is itself a consequential outcome (invariant #1).
    """
    assessment = state["investigation"].get("threat_assessment") or {}
    if assessment.get("verdict") == Verdict.BENIGN.value:
        return TRIAGE
    return CVE_RESEARCH


def triage(state: GraphState) -> dict[str, Any]:
    """Set the investigation's disposition from the assessment and hand it to a human.

    Deliberately *not* a routing decision. SAD §5 anticipates branching on the
    verdict once the downstream fan-out exists; what it must never become is an
    automatic close, because closing an investigation is a consequential outcome
    and invariant #1 reserves those for a person. So triage records what the
    agents concluded and advances to the gate on every path — including benign.
    """
    findings = state["investigation"]
    assessment = findings.get("threat_assessment") or {}
    verdict = str(assessment.get("verdict", "")) or "not assessed"
    priority = str(assessment.get("triage_priority", "")) or "unset"
    detail = f"advanced to gate (verdict={verdict}, priority={priority}"

    dossier = findings.get("vulnerability_dossier")
    detail += (
        f", {len(dossier.get('cves', []))} confirmed CVE(s)" if dossier else ", no CVE research"
    )
    detail += ")"

    return {
        "status": InvestigationStatus.AWAITING_APPROVAL.value,
        "current_node": TRIAGE,
        "updated_at": _utcnow(),
        "node_history": [_transition(TRIAGE, _OWNER_RUNTIME, "completed", detail)],
    }


def human_gate(state: GraphState) -> dict[str, Any]:
    """First-class human approval interrupt.

    Execution pauses here and a resumable checkpoint is persisted; the backend/UI
    sees "awaiting human". On resume the recorded decision is consumed and appended
    to the conversation record for audit. No consequential action node is reachable
    without traversing this gate (invariant #1).

    The payload carries the assessment's headline so the analyst is deciding on a
    stated finding rather than on an opaque prompt, and it flags an escalated case
    explicitly — a low-confidence critical must not look like a routine approval.
    """
    decision = cast(
        "dict[str, Any]",
        interrupt(
            {
                "kind": "human_approval",
                "investigation_id": state["investigation_id"],
                "reason": "awaiting analyst approval before any consequential action",
                **_gate_summary(state),
            }
        ),
    )
    return {
        "current_node": HUMAN_GATE,
        "updated_at": _utcnow(),
        "conversation": {"human_decisions": [decision]},
        "node_history": [
            _transition(HUMAN_GATE, _OWNER_HUMAN, "completed", f"decision={decision['decision']}")
        ],
    }


def _gate_summary(state: GraphState) -> dict[str, Any]:
    """What the analyst is being asked to weigh, drawn from the assessment."""
    assessment = state["investigation"].get("threat_assessment")
    if not assessment:
        return {"assessed": False}

    severity = assessment.get("severity") or {}
    dossier = state["investigation"].get("vulnerability_dossier") or {}
    return {
        "assessed": True,
        "verdict": assessment.get("verdict"),
        "severity": severity.get("level"),
        "severity_score": severity.get("score"),
        "triage_priority": assessment.get("triage_priority"),
        "confidence": assessment.get("confidence"),
        "enrichment_status": assessment.get("enrichment_status"),
        "escalation_required": bool(assessment.get("escalation_required")),
        "escalation_reason": assessment.get("escalation_reason"),
        "confirmed_cves": [item["record"]["cve_id"] for item in dossier.get("cves", [])],
        "candidate_cve_count": len(dossier.get("candidates", [])),
        "cve_research_stale": bool(dossier.get("stale")) if dossier else None,
    }


def close(state: GraphState) -> dict[str, Any]:
    """Terminal node: finalize and persist the investigation status."""
    return {
        "status": InvestigationStatus.CLOSED.value,
        "current_node": CLOSE,
        "updated_at": _utcnow(),
        "node_history": [_transition(CLOSE, _OWNER_RUNTIME, "completed", "investigation closed")],
    }


def route_after_gate(state: GraphState) -> str:
    """Branch on the recorded human decision (EDS §5 conditional routing).

    approve/edit → close; reject → close; redirect → re-enter ``triage`` (a
    rollback-by-retain redirect that re-runs the pipeline rather than mutating
    history).
    """
    decisions = state["conversation"]["human_decisions"]
    if decisions and decisions[-1].get("decision") == DecisionType.REDIRECT.value:
        return TRIAGE
    return CLOSE

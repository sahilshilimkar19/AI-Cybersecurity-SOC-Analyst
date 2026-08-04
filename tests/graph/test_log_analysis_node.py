"""Tests for the Log Analyzer graph node.

The node is where the agent meets the deterministic control plane: it must write
only its own slice of state, surface gaps, and leave the human gate intact.
"""

from graph.runtime import InvestigationGraphService
from models.enums import InvestigationStatus

EVIDENCE = {
    "raw_records": [
        {
            "record_id": "r1",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": (
                "Oct  7 12:34:56 web-01 sshd[1]: Failed password for invalid user admin "
                "from 203.0.113.9 port 22 ssh2"
            ),
            "raw_ref": "auth.log#L1",
            "received_at": "2024-10-07T12:45:00Z",
        },
        {
            "record_id": "r2",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": (
                '{"timestamp":"2024-10-07T12:36:00Z","host":"web-01","user":"deploy",'
                '"message":"New process created: powershell.exe"}'
            ),
            "raw_ref": "auth.log#L2",
        },
        {
            "record_id": "r3",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": "@@@ unparseable @@@",
            "received_at": "2024-10-07T12:45:00Z",
        },
    ],
    "requested_sources": ["hostlogs", "winlogs"],
    "source_failures": [{"source_id": "siem", "reason": "unreachable", "detail": "timeout"}],
}


def test_node_runs_between_seeding_and_triage(service: InvestigationGraphService) -> None:
    result = service.start(investigation_id="inv-1", trigger_source="alert", evidence=EVIDENCE)
    assert [t["node"] for t in result.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "triage",
    ]


def test_node_is_owned_by_the_log_analyzer(service: InvestigationGraphService) -> None:
    result = service.start(investigation_id="inv-1", trigger_source="alert", evidence=EVIDENCE)
    transition = next(t for t in result.node_history if t["node"] == "log_analysis")
    assert transition["owner"] == "log-analyzer"


def test_the_pipeline_still_pauses_at_the_human_gate(
    service: InvestigationGraphService,
) -> None:
    """Adding an agent must not create a path around the approval gate."""
    result = service.start(investigation_id="inv-1", trigger_source="alert", evidence=EVIDENCE)
    assert result.awaiting_human is True
    assert result.status == InvestigationStatus.AWAITING_APPROVAL.value

    approved = service.resume(investigation_id="inv-1", decision="approve")
    assert approved.status == InvestigationStatus.CLOSED.value
    assert [t["node"] for t in approved.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "triage",
        "human_gate",
        "close",
    ]


def test_an_investigation_with_no_evidence_still_completes(
    service: InvestigationGraphService,
) -> None:
    result = service.start(investigation_id="inv-empty", trigger_source="analyst")
    assert result.awaiting_human is True

    closed = service.resume(investigation_id="inv-empty", decision="approve")
    assert closed.status == InvestigationStatus.CLOSED.value


def test_node_records_findings_and_gaps_in_state(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=EVIDENCE)
    values = service.raw_state("inv-1")

    findings = values["investigation"]
    assert len(findings["normalized_events"]) == 2
    assert len(findings["timeline"]) == 2
    gap_text = " ".join(findings["coverage_gaps"])
    assert "source_unavailable" in gap_text
    assert "source_empty" in gap_text
    assert "parse_failure" in gap_text


def test_node_writes_only_its_own_agent_record(
    service: InvestigationGraphService,
) -> None:
    """Writer isolation: the Log Analyzer owns exactly one key in ``agents``."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=EVIDENCE)
    agents = service.raw_state("inv-1")["agents"]

    record = agents["log_analyzer"]
    assert record["confidence"] > 0
    assert record["last_output"]["quarantined"] == 1
    assert record["last_output"]["prompt_version"] == "1.0.0"


def test_raw_evidence_is_left_untouched(service: InvestigationGraphService) -> None:
    """What was ingested must stay distinguishable from what was concluded."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=EVIDENCE)
    evidence = service.raw_state("inv-1")["evidence"]

    assert len(evidence["raw_records"]) == 3
    assert evidence["requested_sources"] == ["hostlogs", "winlogs"]

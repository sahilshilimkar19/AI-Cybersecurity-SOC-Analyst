"""Tests for the Incident Reporter graph node.

The report is the last thing produced before a human is asked to decide, so what
these tests pin is that it exists on *every* path and that the gate carries it.
"""

from graph.runtime import InvestigationGraphService
from models.enums import InvestigationStatus

INTRUSION_EVIDENCE = {
    "raw_records": [
        *(
            {
                "record_id": f"r{index}",
                "source_id": "hostlogs",
                "source_kind": "file",
                "content": (
                    f"Mar  4 09:0{index}:00 web-01 sshd[120{index}]: Failed password for admin "
                    "from 203.0.113.44 port 51122 ssh2"
                ),
                "raw_ref": f"auth.log#L{index}",
                "received_at": "2026-03-04T09:30:00Z",
            }
            for index in range(5)
        ),
        {
            "record_id": "r5",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": (
                "Mar  4 09:05:00 web-01 sshd[1206]: Accepted password for admin "
                "from 203.0.113.44 port 51132 ssh2"
            ),
            "raw_ref": "auth.log#L5",
            "received_at": "2026-03-04T09:30:00Z",
        },
    ],
    "requested_sources": ["hostlogs"],
}

QUIET_EVIDENCE = {
    "raw_records": [
        {
            "record_id": "q1",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": (
                "Mar  4 09:00:00 web-01 sshd[900]: Accepted publickey for deploy "
                "from 10.0.0.9 port 40100 ssh2"
            ),
            "raw_ref": "auth.log#L1",
            "received_at": "2026-03-04T09:30:00Z",
        }
    ],
    "requested_sources": ["hostlogs"],
}


def test_the_node_runs_on_the_threat_path(service: InvestigationGraphService) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    assert [t["node"] for t in result.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "cve_research",
        "report",
        "triage",
    ]


def test_the_node_runs_on_the_benign_path_too(service: InvestigationGraphService) -> None:
    """An investigation that leaves no document behind cannot be reviewed."""
    result = service.start(
        investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE
    )
    nodes = [t["node"] for t in result.node_history]

    assert "cve_research" not in nodes
    assert "report" in nodes


def test_the_node_is_owned_by_the_incident_reporter(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    transition = next(t for t in result.node_history if t["node"] == "report")

    assert transition["owner"] == "incident-reporter"
    assert "finding(s)" in transition["detail"]


def test_both_documents_are_written_into_the_report_substate(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    report = service.raw_state("inv-1")["report"]

    assert report["executive_summary"]
    assert report["technical_report"].startswith("# ")
    assert report["report_status"] == "draft"


def test_the_report_is_a_draft_until_a_human_decides(
    service: InvestigationGraphService,
) -> None:
    """An agent has no authority to mark its own output approved (invariant #1)."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    assert service.raw_state("inv-1")["report"]["report_status"] == "draft"


def test_citations_are_carried_into_state(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    citations = service.raw_state("inv-1")["report"]["citations"]

    assert citations
    assert all("source_id" in citation for citation in citations)


def test_the_node_writes_only_its_own_agent_record(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    agents = service.raw_state("inv-1")["agents"]

    record = agents["incident_reporter"]
    assert record["last_output"]["prompt_version"] == "1.0.0"
    assert record["last_output"]["affected_assets"] == ["web-01"]


def test_the_findings_survive_being_reported(service: InvestigationGraphService) -> None:
    """The report reads state; it must not consume or rewrite it."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    findings = service.raw_state("inv-1")["investigation"]

    assert findings["normalized_events"]
    assert findings["threat_assessment"]["verdict"] in {"suspicious", "malicious"}


def test_triage_records_that_a_report_exists(service: InvestigationGraphService) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    transition = next(t for t in result.node_history if t["node"] == "triage")
    assert "report drafted" in transition["detail"]


def test_the_gate_carries_the_summary_it_asks_a_human_to_approve(
    service: InvestigationGraphService,
) -> None:
    """An analyst approves a document, not a percentage."""
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    pending = result.pending_interrupt

    assert pending is not None
    assert pending["report_status"] == "draft"
    assert "no action has been taken" in pending["executive_summary"]


def test_an_investigation_with_no_evidence_still_produces_a_report(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-empty", trigger_source="analyst")
    report = service.raw_state("inv-empty")["report"]

    assert report["technical_report"]
    assert "No timeline could be reconstructed" in report["technical_report"]


def test_critical_assets_from_the_snapshot_reach_the_report(
    service: InvestigationGraphService,
) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        config_snapshot={"critical_assets": ["web-01"]},
        evidence=INTRUSION_EVIDENCE,
    )
    body = service.raw_state("inv-1")["report"]["technical_report"]
    assert "| web-01 | yes |" in body


def test_adding_a_fourth_agent_created_no_path_around_the_gate(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    approved = service.resume(investigation_id="inv-1", decision="approve")

    assert approved.status == InvestigationStatus.CLOSED.value
    assert [t["node"] for t in approved.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "cve_research",
        "report",
        "triage",
        "human_gate",
        "close",
    ]

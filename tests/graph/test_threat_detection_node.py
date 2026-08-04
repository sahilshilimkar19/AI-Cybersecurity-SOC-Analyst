"""Tests for the Threat Detector graph node.

The node is where the assessment meets the deterministic control plane: it must
write only its own slice of state, leave the evidence untouched, inform the human
gate, and create no path around it.
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
        {
            "record_id": "r6",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": (
                '{"timestamp":"2026-03-04T09:07:00Z","host":"web-01","user":"admin",'
                '"message":"New process created: powershell.exe -nop -w hidden -enc SQBFAFgA"}'
            ),
            "raw_ref": "auth.log#L6",
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


def test_the_node_runs_between_log_analysis_and_triage(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    assert [t["node"] for t in result.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "triage",
    ]


def test_the_node_is_owned_by_the_threat_detector(service: InvestigationGraphService) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    transition = next(t for t in result.node_history if t["node"] == "threat_detection")
    assert transition["owner"] == "threat-detector"
    assert "verdict=" in transition["detail"]


def test_the_assessment_is_written_into_the_findings(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    findings = service.raw_state("inv-1")["investigation"]

    assessment = findings["threat_assessment"]
    assert assessment["verdict"] in {"suspicious", "malicious"}
    assert assessment["severity"]["level"]
    assert assessment["attack_techniques"]
    assert assessment["signals"]


def test_the_node_writes_its_own_agent_record_alongside_the_analyzers(
    service: InvestigationGraphService,
) -> None:
    """Writer isolation: two agents, two keys, neither overwriting the other."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    agents = service.raw_state("inv-1")["agents"]

    assert set(agents) == {"log_analyzer", "threat_detector"}
    record = agents["threat_detector"]
    assert record["confidence"] > 0
    assert record["last_output"]["prompt_version"] == "1.0.0"
    assert record["last_output"]["attack_techniques"]


def test_the_evidence_and_the_timeline_are_left_untouched(
    service: InvestigationGraphService,
) -> None:
    """What was ingested and what was observed must survive being assessed."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    values = service.raw_state("inv-1")

    assert len(values["evidence"]["raw_records"]) == 7
    assert len(values["investigation"]["normalized_events"]) == 7
    assert len(values["investigation"]["timeline"]) == 7


def test_triage_records_the_verdict_it_is_handing_over(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    transition = next(t for t in result.node_history if t["node"] == "triage")
    assert "verdict=" in transition["detail"]
    assert "priority=" in transition["detail"]


def test_the_human_gate_is_told_what_it_is_being_asked_to_approve(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    pending = result.pending_interrupt

    assert pending is not None
    assert pending["assessed"] is True
    assert pending["verdict"] in {"suspicious", "malicious"}
    assert pending["severity"]
    assert pending["triage_priority"]
    assert "escalation_required" in pending


def test_a_benign_investigation_still_pauses_at_the_gate(
    service: InvestigationGraphService,
) -> None:
    """Closing an investigation is consequential; no verdict may bypass a human."""
    result = service.start(
        investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE
    )
    assessment = service.raw_state("inv-quiet")["investigation"]["threat_assessment"]

    assert assessment["verdict"] == "benign"
    assert result.awaiting_human is True
    assert result.status == InvestigationStatus.AWAITING_APPROVAL.value


def test_adding_a_second_agent_created_no_path_around_the_gate(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
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


def test_an_investigation_with_no_evidence_is_assessed_benign_and_completes(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-empty", trigger_source="analyst")
    assessment = service.raw_state("inv-empty")["investigation"]["threat_assessment"]

    assert assessment["verdict"] == "benign"
    assert assessment["confidence"] == 0.0
    closed = service.resume(investigation_id="inv-empty", decision="approve")
    assert closed.status == InvestigationStatus.CLOSED.value


def test_estate_context_is_read_from_the_pinned_config_snapshot(
    service: InvestigationGraphService,
) -> None:
    """A replayed investigation must be assessed against the estate it ran against."""
    service.start(
        investigation_id="inv-critical",
        trigger_source="alert",
        config_snapshot={"critical_assets": ["web-01"], "internal_networks": ["10.0.0.0/8"]},
        evidence=INTRUSION_EVIDENCE,
    )
    assessment = service.raw_state("inv-critical")["investigation"]["threat_assessment"]

    assert assessment["triage_priority"] in {"high", "urgent"}
    assert any("web-01" in factor for factor in assessment["severity"]["factors"])


def test_the_gate_payload_reports_an_unassessed_investigation_honestly() -> None:
    """A missing assessment must read as "not assessed", never as implicitly fine."""
    from graph.nodes import _gate_summary

    assert _gate_summary({"investigation": {"threat_assessment": None}}) == {"assessed": False}  # type: ignore[typeddict-item]

"""Tests for the Patch Recommendation graph node.

The pipeline is complete here, so these tests pin the property the whole design
exists for: the plan's only route onward is through a human.
"""

from graph.registry import node_registry
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
                '{"timestamp":"2026-03-04T09:09:00Z","host":"web-01","user":"SYSTEM",'
                '"message":"The audit log was cleared"}'
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

ASSETS = [{"hostname": "web-01", "software": [{"product": "Apache Log4j", "version": "2.14.1"}]}]


# --- Placement --------------------------------------------------------------


def test_the_node_runs_after_the_report(service: InvestigationGraphService) -> None:
    result = service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    nodes = [t["node"] for t in result.node_history]

    assert nodes.index("remediation") == nodes.index("report") + 1
    assert nodes[-1] == "triage"


def test_the_node_runs_on_the_benign_path_too(service: InvestigationGraphService) -> None:
    """Unlike CVE research there is no external work to save, and the statement matters."""
    result = service.start(
        investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE
    )
    assert "remediation" in [t["node"] for t in result.node_history]


def test_the_node_is_owned_by_the_patch_recommender(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    transition = next(t for t in result.node_history if t["node"] == "remediation")

    assert transition["owner"] == "patch-recommender"
    assert "pending human approval" in transition["detail"]


# --- No path to execution ---------------------------------------------------


def test_nothing_downstream_of_remediation_acts(service: InvestigationGraphService) -> None:
    """The plan's only route onward is the human gate (invariants #1 and #2)."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    approved = service.resume(investigation_id="inv-1", decision="approve")
    nodes = [t["node"] for t in approved.node_history]

    assert nodes[nodes.index("remediation") + 1 :] == ["triage", "human_gate", "close"]
    assert approved.status == InvestigationStatus.CLOSED.value


def test_the_pipeline_contains_no_node_that_executes() -> None:
    """A registry entry named for an action is how this platform would go wrong."""
    forbidden = {"execute", "apply", "remediate", "patch", "isolate", "block", "quarantine"}
    for spec in node_registry():
        assert not forbidden & set(spec.name.split("_")), spec.name


def test_every_stored_recommendation_is_pending(service: InvestigationGraphService) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    plan = service.raw_state("inv-1")["investigation"]["remediation_plan"]

    assert plan["requires_human_approval"] is True
    assert all(item["approval_status"] == "pending" for item in plan["recommendations"])


# --- State ------------------------------------------------------------------


def test_the_plan_is_written_into_the_findings(service: InvestigationGraphService) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    plan = service.raw_state("inv-1")["investigation"]["remediation_plan"]

    assert plan["recommendations"]
    assert plan["overall_risk"]["score"] > 0


def test_the_node_writes_only_its_own_agent_record(
    service: InvestigationGraphService,
) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    agents = service.raw_state("inv-1")["agents"]

    assert set(agents) == {
        "log_analyzer",
        "threat_detector",
        "cve_research",
        "incident_reporter",
        "patch_recommender",
    }
    record = agents["patch_recommender"]
    assert record["last_output"]["prompt_version"] == "1.0.0"
    assert record["last_output"]["requires_human_approval"] is True


def test_the_report_and_the_findings_survive_being_remediated(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    values = service.raw_state("inv-1")

    assert values["report"]["technical_report"]
    assert values["investigation"]["threat_assessment"]["verdict"] in {
        "suspicious",
        "malicious",
    }


def test_critical_assets_from_the_snapshot_reach_the_plan(
    service: InvestigationGraphService,
) -> None:
    plain = service.start(
        investigation_id="inv-plain",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    critical = service.start(
        investigation_id="inv-critical",
        trigger_source="alert",
        config_snapshot={"critical_assets": ["web-01"]},
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    assert plain.investigation_id != critical.investigation_id

    plain_risk = service.raw_state("inv-plain")["investigation"]["remediation_plan"]
    critical_risk = service.raw_state("inv-critical")["investigation"]["remediation_plan"]
    assert critical_risk["overall_risk"]["score"] >= plain_risk["overall_risk"]["score"]


def test_a_benign_investigation_records_that_there_is_nothing_to_fix(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE)
    plan = service.raw_state("inv-quiet")["investigation"]["remediation_plan"]

    assert plan["recommendations"] == []
    assert plan["notes"]


# --- The gate ---------------------------------------------------------------


def test_the_gate_states_what_it_is_authorizing(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    pending = result.pending_interrupt

    assert pending is not None
    assert pending["recommendation_count"] > 0
    assert pending["highest_recommendation_priority"]
    assert pending["recommendations_pending_approval"] is True


def test_the_gate_distinguishes_no_plan_from_an_empty_plan(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE
    )
    pending = result.pending_interrupt

    assert pending is not None
    assert pending["recommendation_count"] == 0
    assert pending["recommendations_pending_approval"] is False


def test_triage_records_the_recommendation_count(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    transition = next(t for t in result.node_history if t["node"] == "triage")
    assert "recommendation(s)" in transition["detail"]

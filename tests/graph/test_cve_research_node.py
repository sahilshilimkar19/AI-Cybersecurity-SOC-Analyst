"""Tests for the CVE Research node and the verdict branch that reaches it.

The branch is the first place SAD §5's conditional routing does real work. What
these tests pin is the distinction that makes it safe: it skips *work*, never the
*gate*.
"""

from graph.nodes import route_after_threat
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
            "received_at": "2026-03-04T09:30:00Z",
        },
        {
            "record_id": "r6",
            "source_id": "hostlogs",
            "source_kind": "file",
            "content": (
                '{"timestamp":"2026-03-04T09:07:00Z","host":"web-01","user":"admin",'
                '"message":"scanner flagged CVE-2021-44228 on this host"}'
            ),
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
            "received_at": "2026-03-04T09:30:00Z",
        }
    ],
    "requested_sources": ["hostlogs"],
}

ASSETS = [
    {
        "hostname": "web-01",
        "operating_system": "Ubuntu 22.04",
        "software": [{"product": "Apache Log4j", "version": "2.14.1"}],
    }
]


# --- The verdict branch -----------------------------------------------------


def test_a_benign_verdict_skips_research() -> None:
    """Researching CVEs for activity nothing flagged spends budget on no question."""
    state = {"investigation": {"threat_assessment": {"verdict": "benign"}}}
    assert route_after_threat(state) == "report"  # type: ignore[arg-type]


def test_a_suspicious_or_malicious_verdict_earns_the_deeper_work() -> None:
    for verdict in ("suspicious", "malicious"):
        state = {"investigation": {"threat_assessment": {"verdict": verdict}}}
        assert route_after_threat(state) == "cve_research"  # type: ignore[arg-type]


def test_a_missing_assessment_does_not_silently_skip_research() -> None:
    """Absent an assessment the conservative branch is the one that does the work."""
    state: dict[str, object] = {"investigation": {}}
    assert route_after_threat(state) == "cve_research"  # type: ignore[arg-type]


def test_the_benign_path_still_reaches_the_human_gate(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE
    )
    nodes = [t["node"] for t in result.node_history]

    assert "cve_research" not in nodes
    assert nodes == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "report",
        "remediation",
        "triage",
    ]
    assert result.awaiting_human is True
    assert result.status == InvestigationStatus.AWAITING_APPROVAL.value


def test_a_skipped_investigation_records_no_dossier(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE)
    findings = service.raw_state("inv-quiet")["investigation"]

    assert findings["vulnerability_dossier"] is None
    assert "cve_research" not in service.raw_state("inv-quiet")["agents"]


# --- The node ---------------------------------------------------------------


def test_the_node_runs_between_threat_detection_and_triage(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    assert [t["node"] for t in result.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "cve_research",
        "report",
        "remediation",
        "triage",
    ]


def test_the_node_is_owned_by_cve_research(service: InvestigationGraphService) -> None:
    result = service.start(
        investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE
    )
    transition = next(t for t in result.node_history if t["node"] == "cve_research")

    assert transition["owner"] == "cve-research"
    assert "candidate" in transition["detail"]


def test_the_dossier_is_written_into_the_findings(
    service: InvestigationGraphService,
) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    dossier = service.raw_state("inv-1")["investigation"]["vulnerability_dossier"]

    assert dossier is not None
    assert dossier["searched_products"] == ["Apache Log4j"]
    assert dossier["stale"] is True


def test_a_cve_named_in_a_log_line_is_picked_up_and_researched(
    service: InvestigationGraphService,
) -> None:
    """Identifiers in the evidence are looked up, never believed (invariant #3)."""
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    agents = service.raw_state("inv-1")["agents"]

    assert agents["cve_research"]["tool_calls"][0] == {"tool": "fetch_cve", "count": 1}


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
    record = agents["cve_research"]
    assert record["last_output"]["prompt_version"] == "1.0.0"
    assert record["last_output"]["searched_products"] == ["Apache Log4j"]


def test_the_assessment_and_the_evidence_survive_being_researched(
    service: InvestigationGraphService,
) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    values = service.raw_state("inv-1")

    assert len(values["evidence"]["raw_records"]) == 7
    assert values["investigation"]["threat_assessment"]["verdict"] in {
        "suspicious",
        "malicious",
    }


# --- Asset seeding ----------------------------------------------------------


def test_the_inventory_is_seeded_into_the_shared_blackboard(
    service: InvestigationGraphService,
) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    assert service.raw_state("inv-1")["shared"]["assets"] == ASSETS


def test_without_an_inventory_research_still_runs_and_confirms_nothing(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="alert", evidence=INTRUSION_EVIDENCE)
    dossier = service.raw_state("inv-1")["investigation"]["vulnerability_dossier"]

    assert dossier["cves"] == []
    assert dossier["searched_products"] == []


def test_a_malformed_inventory_entry_is_counted_not_fatal(
    service: InvestigationGraphService,
) -> None:
    result = service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=[*ASSETS, {"not": "an asset"}],
    )
    transition = next(t for t in result.node_history if t["node"] == "cve_research")

    assert "1 asset record(s) unreadable" in transition["detail"]


# --- The gate ---------------------------------------------------------------


def test_the_gate_is_told_what_research_found(service: InvestigationGraphService) -> None:
    result = service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    pending = result.pending_interrupt

    assert pending is not None
    assert "confirmed_cves" in pending
    assert pending["cve_research_stale"] is True


def test_the_gate_distinguishes_research_skipped_from_research_empty(
    service: InvestigationGraphService,
) -> None:
    """A benign case that never researched must not read as "researched, found nothing"."""
    result = service.start(
        investigation_id="inv-quiet", trigger_source="analyst", evidence=QUIET_EVIDENCE
    )
    pending = result.pending_interrupt

    assert pending is not None
    assert pending["cve_research_stale"] is None
    assert pending["confirmed_cves"] == []


def test_adding_a_third_agent_created_no_path_around_the_gate(
    service: InvestigationGraphService,
) -> None:
    service.start(
        investigation_id="inv-1",
        trigger_source="alert",
        evidence=INTRUSION_EVIDENCE,
        assets=ASSETS,
    )
    approved = service.resume(investigation_id="inv-1", decision="approve")

    assert approved.status == InvestigationStatus.CLOSED.value
    assert [t["node"] for t in approved.node_history] == [
        "ingest_seed",
        "log_analysis",
        "threat_detection",
        "cve_research",
        "report",
        "remediation",
        "triage",
        "human_gate",
        "close",
    ]

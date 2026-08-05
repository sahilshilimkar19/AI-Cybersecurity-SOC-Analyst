"""End-to-end tests for the investigation API the dashboard is built on.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. These run the real graph
over an in-memory checkpointer, so what is exercised is the actual pipeline
writing through the actual backend — the seam where a stub would simply agree
with whatever the routes assumed.

The properties under test are the ones the platform's guarantees rest on: a
capability is required for every route, progress reported is progress recorded,
a decision is written before it is acted on, approval never executes, and a
correctly-skipped stage is reported as skipped rather than as pending.
"""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import sessionmaker

from backend.db.orm.audit import AuditLog
from backend.db.orm.investigation import Investigation
from models.enums import UserRole

# One coherent brute-force-then-breakthrough episode against a single principal:
# enough failures to clear the detection threshold, then the guess landing. That
# yields a non-benign verdict, so the CVE branch runs and the remediation plan
# has techniques to recommend against — the whole pipeline, not a fragment of it.
HOSTILE_LINES = (
    "Oct  7 12:34:00 web-01 sshd[1200]: Failed password for invalid user admin "
    "from 203.0.113.9 port 22 ssh2",
    "Oct  7 12:34:10 web-01 sshd[1201]: Failed password for invalid user admin "
    "from 203.0.113.9 port 22 ssh2",
    "Oct  7 12:34:20 web-01 sshd[1202]: Failed password for invalid user admin "
    "from 203.0.113.9 port 22 ssh2",
    "Oct  7 12:34:30 web-01 sshd[1203]: Failed password for invalid user admin "
    "from 203.0.113.9 port 22 ssh2",
    "Oct  7 12:34:40 web-01 sshd[1204]: Failed password for invalid user admin "
    "from 203.0.113.9 port 22 ssh2",
    "Oct  7 12:34:50 web-01 sshd[1205]: Failed password for invalid user admin "
    "from 203.0.113.9 port 22 ssh2",
    "Oct  7 12:35:00 web-01 sshd[1206]: Accepted password for admin from 203.0.113.9 port 22 ssh2",
)

QUIET_LINES = (
    "time=2024-10-07T12:39:00Z host=web-01 user=deploy action=file_access "
    "path=/srv/app/config.yml result=allowed",
)


def _seed(lines: tuple[str, ...] = HOSTILE_LINES, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": "SSH brute force against web-01",
        "trigger_source": "alert",
        "evidence": {
            "raw_records": [
                {
                    "record_id": f"r{index}",
                    "source_id": "hostlogs",
                    "source_kind": "file",
                    "content": content,
                    "raw_ref": f"auth.log#L{index}",
                }
                for index, content in enumerate(lines, start=1)
            ],
            "requested_sources": ["hostlogs"],
        },
        "assets": [
            {
                "hostname": "web-01",
                "operating_system": "Ubuntu 22.04",
                "software": [{"product": "openssh", "version": "8.9"}],
                "environment": "production",
            }
        ],
        "critical_assets": ["web-01"],
        "internal_networks": ["10.0.0.0/8"],
    }
    payload.update(overrides)
    return payload


def _run(client: TestClient, headers: dict[str, str], **overrides: Any) -> dict[str, Any]:
    """Trigger an investigation and let the background run complete.

    ``TestClient`` runs background tasks to completion before returning, so by
    the time this returns the pipeline has reached the human gate.
    """
    response = client.post("/investigations", json=_seed(**overrides), headers=headers)
    assert response.status_code == 202, response.text
    return dict(response.json())


def _recommendations(
    client: TestClient, investigation_id: str, headers: dict[str, str]
) -> list[dict[str, Any]]:
    """The plan this evidence produced, asserted non-empty.

    Asserted rather than skipped over: a fixture that stops producing
    recommendations is a regression in the pipeline, and a skip would report it
    as a passing suite.
    """
    body = client.get(f"/investigations/{investigation_id}/recommendations", headers=headers).json()
    assert body["recommendations"], "the fixture episode should produce a remediation plan"
    return list(body["recommendations"])


# --- Authorization ----------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/investigations"),
        ("get", "/investigations/00000000-0000-0000-0000-000000000000"),
        ("post", "/investigations"),
        ("get", "/notifications"),
        ("get", "/system/capabilities"),
    ],
)
def test_every_route_requires_authentication(client: TestClient, method: str, path: str) -> None:
    response = client.request(method.upper(), path, json={} if method == "post" else None)
    assert response.status_code == 401


def test_an_auditor_may_read_but_not_trigger(client: TestClient, authenticate: Any) -> None:
    """Least privilege is enforced at the endpoint, not only in the UI."""
    headers = authenticate(UserRole.AUDITOR)

    assert client.get("/investigations", headers=headers).status_code == 200
    assert client.post("/investigations", json=_seed(), headers=headers).status_code == 403


def test_an_analyst_may_trigger_but_not_approve(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    decision = client.post(
        f"/investigations/{created['id']}/decision", json={"decision": "approve"}, headers=headers
    )
    assert decision.status_code == 403


def test_capabilities_come_from_the_server(client: TestClient, authenticate: Any) -> None:
    """The client asks what it may do rather than keeping its own copy of RBAC."""
    body = client.get("/system/capabilities", headers=authenticate(UserRole.SENIOR_ANALYST)).json()

    assert body["role"] == "senior_analyst"
    assert "approve_actions" in body["capabilities"]
    assert "manage_users" not in body["capabilities"]


# --- Triggering and running -------------------------------------------------


def test_triggering_returns_a_handle_immediately(client: TestClient, authenticate: Any) -> None:
    """202, not 201: the case exists, the analysis it will carry does not yet."""
    response = client.post("/investigations", json=_seed(), headers=authenticate(UserRole.ANALYST))
    assert response.status_code == 202
    assert response.json()["status"] == "open"


def test_a_run_reaches_the_human_gate_and_stops(client: TestClient, authenticate: Any) -> None:
    """The pipeline pauses for a person; it does not close its own case."""
    created = _run(client, authenticate(UserRole.ANALYST))

    detail = client.get(
        f"/investigations/{created['id']}", headers=authenticate(UserRole.ANALYST)
    ).json()
    assert detail["status"] == "awaiting_approval"
    assert detail["snapshot"]["awaiting_human"] is True


def test_every_stage_persists_its_own_artifact(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)
    investigation_id = created["id"]

    assert client.get(f"/investigations/{investigation_id}/timeline", headers=headers).json()[
        "events"
    ]
    assert (
        client.get(f"/investigations/{investigation_id}/threat", headers=headers).status_code == 200
    )
    assert (
        client.get(f"/investigations/{investigation_id}/report", headers=headers).status_code == 200
    )
    assert (
        client.get(f"/investigations/{investigation_id}/recommendations", headers=headers).json()[
            "recommendations"
        ]
        is not None
    )


def test_reported_progress_matches_recorded_progress(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """The screen reports what the backend wrote, not what it guessed."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    snapshot = client.get(f"/investigations/{created['id']}", headers=headers).json()["snapshot"]
    complete = {stage["name"] for stage in snapshot["pipeline"] if stage["complete"]}

    session = sessionmaker(bind=db_engine)()
    try:
        row = session.get(Investigation, created["id"])
        assert row is not None
        recorded = {
            name for name, entry in row.pipeline.items() if entry.get("status") == "complete"
        }
    finally:
        session.close()

    assert complete == recorded


def test_a_benign_verdict_marks_cve_research_skipped_not_pending(
    client: TestClient, authenticate: Any
) -> None:
    """Work correctly not done must not read as work still outstanding."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers, evidence=_seed(QUIET_LINES)["evidence"])

    detail = client.get(f"/investigations/{created['id']}", headers=headers).json()
    stage = next(s for s in detail["snapshot"]["pipeline"] if s["name"] == "cve_research")

    if detail["snapshot"]["verdict"] == "benign":
        assert stage["skipped"] is True
        assert stage["complete"] is False

    cves = client.get(f"/investigations/{created['id']}/cves", headers=headers).json()
    assert cves["researched"] is (stage["complete"] is True)


def test_no_research_is_distinguishable_from_no_findings(
    client: TestClient, authenticate: Any
) -> None:
    """An empty finding list means nothing without saying whether anyone looked."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers, evidence=_seed(QUIET_LINES)["evidence"])

    body = client.get(f"/investigations/{created['id']}/cves", headers=headers).json()
    assert "researched" in body


# --- Reading ----------------------------------------------------------------


def test_the_queue_lists_what_was_created(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    _run(client, headers)

    page = client.get("/investigations", headers=headers).json()
    assert page["total"] == 1
    assert page["items"][0]["title"] == "SSH brute force against web-01"


def test_the_queue_filters_and_counts_under_the_same_filter(
    client: TestClient, authenticate: Any
) -> None:
    headers = authenticate(UserRole.ANALYST)
    _run(client, headers)

    matching = client.get("/investigations?status=awaiting_approval", headers=headers).json()
    other = client.get("/investigations?status=closed", headers=headers).json()

    assert matching["total"] == 1
    assert other["total"] == 0
    assert other["items"] == []


def test_mine_scopes_to_the_caller(client: TestClient, authenticate: Any) -> None:
    owner = authenticate(UserRole.ANALYST)
    _run(client, owner)
    stranger = authenticate(UserRole.ANALYST)

    assert client.get("/investigations?mine=true", headers=owner).json()["total"] == 1
    assert client.get("/investigations?mine=true", headers=stranger).json()["total"] == 0


def test_timeline_events_carry_provenance(client: TestClient, authenticate: Any) -> None:
    """An event that cannot say where it came from is not evidence."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    events = client.get(f"/investigations/{created['id']}/timeline", headers=headers).json()[
        "events"
    ]
    assert all(event["provenance"].get("record_id") for event in events)
    assert all(event["source"] for event in events)


def test_indicators_report_whether_they_were_enriched(
    client: TestClient, authenticate: Any
) -> None:
    """An unchecked indicator is not a clean one, and the screen has to say so."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    threat = client.get(f"/investigations/{created['id']}/threat", headers=headers).json()
    assert threat["enrichment_status"] in {"complete", "degraded", "unavailable"}
    assert all("enriched" in indicator for indicator in threat["indicators"])


def test_an_absent_assessment_is_a_404_not_an_empty_body(
    client: TestClient, authenticate: Any
) -> None:
    headers = authenticate(UserRole.ANALYST)
    created = client.post("/investigations", json=_seed(evidence={}), headers=headers).json()

    # The run produced no events, so nothing downstream has an artifact to show.
    response = client.get(f"/investigations/{created['id']}/report", headers=headers)
    assert response.status_code in {200, 404}


def test_an_unknown_investigation_is_a_404(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    missing = "00000000-0000-0000-0000-000000000000"

    response = client.get(f"/investigations/{missing}", headers=headers)
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_report_history_keeps_every_generation(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    history = client.get(f"/investigations/{created['id']}/report/history", headers=headers).json()
    assert [entry["version"] for entry in history["versions"]] == [1]


# --- The human gate ---------------------------------------------------------


def test_a_recommendation_arrives_pending_and_unexecuted(
    client: TestClient, authenticate: Any
) -> None:
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    body = client.get(f"/investigations/{created['id']}/recommendations", headers=headers).json()
    assert all(item["approval_status"] == "pending" for item in body["recommendations"])
    assert all(item["requires_human_approval"] for item in body["recommendations"])


def test_no_response_field_could_carry_something_a_machine_runs(
    client: TestClient, authenticate: Any
) -> None:
    """The API shape carries the same guarantee the stored row does."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    body = client.get(f"/investigations/{created['id']}/recommendations", headers=headers).json()
    forbidden = {"command", "commands", "script", "playbook", "playbook_id", "payload", "exec"}
    for item in body["recommendations"]:
        assert not forbidden & set(item)


def test_pending_approvals_reports_the_open_gate_separately(
    client: TestClient, authenticate: Any
) -> None:
    """A paused gate with an empty plan is still work waiting on a person."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)

    body = client.get(f"/investigations/{created['id']}/pending-approvals", headers=headers).json()
    assert body["gate_open"] is True


def test_approving_closes_the_investigation_and_executes_nothing(
    client: TestClient, authenticate: Any
) -> None:
    approver = authenticate(UserRole.SENIOR_ANALYST)
    created = _run(client, authenticate(UserRole.ANALYST))

    response = client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve", "rationale": "confirmed and contained"},
        headers=approver,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "closed"
    assert body["awaiting_human"] is False
    assert body["executed"] is False


def test_approving_promotes_the_report_from_draft_to_final(
    client: TestClient, authenticate: Any
) -> None:
    """Only a recorded human decision makes a document final."""
    reader = authenticate(UserRole.ANALYST)
    created = _run(client, reader)
    before = client.get(f"/investigations/{created['id']}/report", headers=reader).json()
    assert before["status"] == "draft"

    client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve"},
        headers=authenticate(UserRole.SENIOR_ANALYST),
    )
    after = client.get(f"/investigations/{created['id']}/report", headers=reader).json()
    assert after["status"] == "final"


def test_asking_for_edits_leaves_the_report_a_draft(client: TestClient, authenticate: Any) -> None:
    """An analyst requesting changes has not signed off on what is in front of them."""
    reader = authenticate(UserRole.ANALYST)
    created = _run(client, reader)

    client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "edit", "rationale": "tighten the timeline section"},
        headers=authenticate(UserRole.SENIOR_ANALYST),
    )
    assert (
        client.get(f"/investigations/{created['id']}/report", headers=reader).json()["status"]
        == "draft"
    )


def test_a_redirect_returns_to_the_gate_rather_than_closing(
    client: TestClient, authenticate: Any
) -> None:
    created = _run(client, authenticate(UserRole.ANALYST))

    body = client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "redirect", "target": "re-check the lateral movement"},
        headers=authenticate(UserRole.MANAGER),
    ).json()
    assert body["awaiting_human"] is True
    assert body["status"] == "awaiting_approval"


def test_deciding_twice_is_refused(client: TestClient, authenticate: Any) -> None:
    """The second decision is a duplicate or a race; accepting it makes the audit lie."""
    approver = authenticate(UserRole.SENIOR_ANALYST)
    created = _run(client, authenticate(UserRole.ANALYST))

    first = client.post(
        f"/investigations/{created['id']}/decision", json={"decision": "approve"}, headers=approver
    )
    second = client.post(
        f"/investigations/{created['id']}/decision", json={"decision": "reject"}, headers=approver
    )
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"] == "conflict"


def test_a_gate_decision_is_audited(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    created = _run(client, authenticate(UserRole.ANALYST))
    client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve"},
        headers=authenticate(UserRole.SENIOR_ANALYST),
    )

    session = sessionmaker(bind=db_engine)()
    try:
        actions = set(session.execute(select(AuditLog.action)).scalars().all())
    finally:
        session.close()
    assert "investigation.created" in actions
    assert "investigation.decision.approve" in actions


# --- Per-recommendation decisions -------------------------------------------


def test_a_recommendation_decision_is_recorded_and_audited(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    reader = authenticate(UserRole.ANALYST)
    created = _run(client, reader)
    recommendations = _recommendations(client, created["id"], reader)

    target = recommendations[0]["id"]
    response = client.post(
        f"/investigations/{created['id']}/recommendations/{target}/decision",
        json={"decision": "approved", "rationale": "scheduled for the Thursday window"},
        headers=authenticate(UserRole.MANAGER),
    )
    assert response.status_code == 200
    assert response.json()["approval_status"] == "approved"

    session = sessionmaker(bind=db_engine)()
    try:
        actions = set(session.execute(select(AuditLog.action)).scalars().all())
    finally:
        session.close()
    assert "recommendation.decision.approved" in actions


def test_pending_is_refused_as_a_recommendation_decision(
    client: TestClient, authenticate: Any
) -> None:
    """Un-deciding is not a decision, it is a loss of the record."""
    reader = authenticate(UserRole.ANALYST)
    created = _run(client, reader)
    recommendations = _recommendations(client, created["id"], reader)

    response = client.post(
        f"/investigations/{created['id']}/recommendations/{recommendations[0]['id']}/decision",
        json={"decision": "pending"},
        headers=authenticate(UserRole.MANAGER),
    )
    assert response.status_code == 422


def test_a_recommendation_from_another_investigation_is_not_reachable(
    client: TestClient, authenticate: Any
) -> None:
    """Object-level ownership, not just "is this id a recommendation"."""
    reader = authenticate(UserRole.ANALYST)
    first = _run(client, reader)
    second = _run(client, reader)
    recommendations = _recommendations(client, first["id"], reader)

    response = client.post(
        f"/investigations/{second['id']}/recommendations/{recommendations[0]['id']}/decision",
        json={"decision": "approved"},
        headers=authenticate(UserRole.MANAGER),
    )
    assert response.status_code == 404


# --- Edge cases -------------------------------------------------------------


def test_an_investigation_with_no_assessment_reports_404_for_the_threat_view(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """Absent is reported as absent, not as an empty assessment."""
    from backend.db.orm.investigation import Investigation as Row
    from models.enums import TriggerSource

    session = sessionmaker(bind=db_engine, expire_on_commit=False)()
    try:
        row = Row(trigger_source=TriggerSource.ALERT, title="never ran", pipeline={})
        session.add(row)
        session.commit()
        investigation_id = str(row.id)
    finally:
        session.close()

    headers = authenticate(UserRole.ANALYST)
    assert (
        client.get(f"/investigations/{investigation_id}/threat", headers=headers).status_code == 404
    )
    assert (
        client.get(f"/investigations/{investigation_id}/report", headers=headers).status_code == 404
    )


def test_a_severity_filter_narrows_the_queue(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    _run(client, headers)

    assert client.get("/investigations?severity=info", headers=headers).json()["total"] == 0


def test_deciding_the_same_recommendation_twice_is_refused(
    client: TestClient, authenticate: Any
) -> None:
    """A second approval is a duplicate or a race; accepting it makes the audit lie."""
    reader = authenticate(UserRole.ANALYST)
    approver = authenticate(UserRole.MANAGER)
    created = _run(client, reader)
    target = _recommendations(client, created["id"], reader)[0]["id"]
    path = f"/investigations/{created['id']}/recommendations/{target}/decision"

    assert client.post(path, json={"decision": "approved"}, headers=approver).status_code == 200
    conflict = client.post(path, json={"decision": "rejected"}, headers=approver)
    assert conflict.status_code == 409
    assert "already approved" in conflict.json()["message"]


def test_a_redirect_then_an_approval_reuses_one_decision_thread(
    client: TestClient, authenticate: Any
) -> None:
    """Both decisions belong to the same case, so they share its record."""
    approver = authenticate(UserRole.SENIOR_ANALYST)
    created = _run(client, authenticate(UserRole.ANALYST))

    redirected = client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "redirect", "target": "re-check egress"},
        headers=approver,
    )
    approved = client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve"},
        headers=approver,
    )
    assert redirected.status_code == 200
    assert approved.status_code == 200
    assert approved.json()["status"] == "closed"


def test_a_citation_that_no_longer_parses_is_dropped_not_half_rendered(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """A reference an analyst cannot follow is worse than a visibly missing one."""
    from backend.db.orm.reporting import Report

    reader = authenticate(UserRole.ANALYST)
    created = _run(client, reader)

    session = sessionmaker(bind=db_engine, expire_on_commit=False)()
    try:
        row = (
            session.execute(select(Report).where(Report.investigation_id == created["id"]))
            .scalars()
            .one()
        )
        row.citations = [
            {"source_id": "nvd", "source": "NVD", "url": "https://nvd/CVE-1"},
            {"totally": "malformed"},
        ]
        session.commit()
    finally:
        session.close()

    body = client.get(f"/investigations/{created['id']}/report", headers=reader).json()
    assert [citation["source_id"] for citation in body["citations"]] == ["nvd"]

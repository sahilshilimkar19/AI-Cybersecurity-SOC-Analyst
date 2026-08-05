"""Integration tests for persisting remediation recommendations.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. The property under test is
the seam between proposing and approving: every row is written pending, only a
recorded human decision moves it, and nothing here executes anything.
"""

import pytest
from sqlalchemy.orm import Session

from backend.db.orm.investigation import Investigation
from backend.db.orm.reporting import Recommendation
from backend.db.repositories.reporting import RecommendationRepository
from backend.services.remediation import (
    decide_recommendation,
    record_remediation_plan,
    to_recommendation,
)
from models.enums import (
    ApprovalStatus,
    RecommendationType,
    Severity,
    TriagePriority,
    TriggerSource,
)
from models.remediation import (
    RemediationConfidence,
    RemediationPlan,
    RemediationRecommendation,
    RemediationSupport,
    RiskScore,
)
from models.values import Citation


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    record = Investigation(trigger_source=TriggerSource.ALERT, title="remediation fixture")
    db_session.add(record)
    db_session.flush()
    return record


def _recommendation(**overrides: object) -> RemediationRecommendation:
    payload: dict[str, object] = {
        "action": "Patch CVE-2021-44228 on log4j-core to 2.17.1",
        "type": RecommendationType.PATCH,
        "priority": TriagePriority.URGENT,
        "risk": RiskScore(score=9.5, level=Severity.CRITICAL, rationale="exploited"),
        "rationale": "Confirmed applicable and a fixed release exists.",
        "expected_impact": "Removes the vulnerability; requires a service restart.",
        "steps": ["Identify every host running log4j-core.", "Upgrade to 2.17.1."],
        "verification": "Confirm the deployed version is 2.17.1.",
        "targets": ["web-01"],
        "support": RemediationSupport(cve_ids=["CVE-2021-44228"]),
        "grounding": RemediationConfidence.VENDOR_SPECIFIC,
        "citations": [Citation(source_id="nvd", source="NVD", url="https://nvd/CVE-2021-44228")],
    }
    payload.update(overrides)
    return RemediationRecommendation(**payload)


def _plan(*items: RemediationRecommendation) -> RemediationPlan:
    return RemediationPlan(
        investigation_id="inv-1", recommendations=list(items) or [_recommendation()]
    )


# --- Writing ----------------------------------------------------------------


def test_a_recommendation_round_trips_with_its_reasoning(
    db_session: Session, investigation: Investigation
) -> None:
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())

    assert row.action.startswith("Patch CVE-2021-44228")
    assert row.priority is TriagePriority.URGENT
    assert "Confirmed applicable" in row.rationale
    assert row.version == 1


def test_the_steps_and_verification_are_stored_as_guidance(
    db_session: Session, investigation: Investigation
) -> None:
    """Stored as prose, not as a task list a runner could iterate."""
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())

    assert "Suggested steps for an analyst:" in row.rationale
    assert "Verification:" in row.rationale
    assert "Grounding: vendor specific." in row.rationale


def test_no_stored_column_could_hold_an_executable(
    db_session: Session, investigation: Investigation
) -> None:
    forbidden = {"command", "script", "playbook", "payload", "exec"}
    assert not forbidden & set(Recommendation.__table__.columns.keys())


def test_every_row_is_written_pending_human_approval(
    db_session: Session, investigation: Investigation
) -> None:
    """Regardless of what the agent produced (invariants #1 and #2)."""
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())

    assert row.approval_status is ApprovalStatus.PENDING
    assert row.requires_human_approval is True


def test_citations_travel_with_the_row(db_session: Session, investigation: Investigation) -> None:
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())
    assert row.citations[0]["url"].endswith("/CVE-2021-44228")


def test_an_empty_plan_writes_no_rows(db_session: Session, investigation: Investigation) -> None:
    plan = RemediationPlan(investigation_id="inv-1")
    assert record_remediation_plan(db_session, investigation.id, plan) == []


# --- Versioning -------------------------------------------------------------


def test_a_re_run_supersedes_the_whole_plan(
    db_session: Session, investigation: Investigation
) -> None:
    record_remediation_plan(db_session, investigation.id, _plan())
    second = record_remediation_plan(
        db_session, investigation.id, _plan(_recommendation(), _recommendation(action="Other"))
    )

    assert {row.version for row in second} == {2}
    repository = RecommendationRepository(db_session)
    assert repository.latest_version(investigation.id) == 2
    assert len(repository.current(investigation.id)) == 2


def test_a_superseded_plan_can_be_read_back_whole(
    db_session: Session, investigation: Investigation
) -> None:
    record_remediation_plan(db_session, investigation.id, _plan())
    record_remediation_plan(db_session, investigation.id, _plan(_recommendation(action="New")))

    first = RecommendationRepository(db_session).for_version(investigation.id, 1)
    assert [row.action for row in first] == ["Patch CVE-2021-44228 on log4j-core to 2.17.1"]


def test_versions_are_isolated_per_investigation(db_session: Session) -> None:
    first = Investigation(trigger_source=TriggerSource.ALERT, title="one")
    second = Investigation(trigger_source=TriggerSource.ALERT, title="two")
    db_session.add_all([first, second])
    db_session.flush()

    record_remediation_plan(db_session, first.id, _plan())
    record_remediation_plan(db_session, first.id, _plan())
    (row,) = record_remediation_plan(db_session, second.id, _plan())

    assert row.version == 1


# --- The approval queue -----------------------------------------------------


def test_pending_approval_lists_the_current_plan_only(
    db_session: Session, investigation: Investigation
) -> None:
    """A superseded plan's pending items are history, not outstanding work."""
    record_remediation_plan(db_session, investigation.id, _plan())
    record_remediation_plan(db_session, investigation.id, _plan(_recommendation(action="New")))

    pending = RecommendationRepository(db_session).pending_approval(investigation.id)
    assert [row.action for row in pending] == ["New"]


def test_an_investigation_with_no_plan_has_nothing_pending(
    db_session: Session, investigation: Investigation
) -> None:
    repository = RecommendationRepository(db_session)
    assert repository.current(investigation.id) == []
    assert repository.pending_approval(investigation.id) == []


# --- Decisions --------------------------------------------------------------


def test_a_human_decision_is_recorded(db_session: Session, investigation: Investigation) -> None:
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())
    decided = decide_recommendation(
        db_session, row.id, decision=ApprovalStatus.APPROVED, actor_id="analyst-7"
    )

    assert decided.approval_status is ApprovalStatus.APPROVED
    assert RecommendationRepository(db_session).pending_approval(investigation.id) == []


@pytest.mark.parametrize(
    "decision", [ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EDITED]
)
def test_every_real_decision_is_accepted(
    db_session: Session, investigation: Investigation, decision: ApprovalStatus
) -> None:
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())
    assert (
        decide_recommendation(
            db_session, row.id, decision=decision, actor_id="analyst-7"
        ).approval_status
        is decision
    )


def test_un_deciding_is_refused(db_session: Session, investigation: Investigation) -> None:
    """Reverting to pending is not a decision, it is a loss of the record."""
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())
    with pytest.raises(ValueError, match="not a decision"):
        decide_recommendation(
            db_session, row.id, decision=ApprovalStatus.PENDING, actor_id="analyst-7"
        )


def test_a_decision_must_record_who_made_it(
    db_session: Session, investigation: Investigation
) -> None:
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())
    with pytest.raises(ValueError, match="who made it"):
        decide_recommendation(db_session, row.id, decision=ApprovalStatus.APPROVED, actor_id="  ")


def test_re_deciding_is_refused(db_session: Session, investigation: Investigation) -> None:
    """A second approval is a duplicate or a race; accepting it makes the audit lie."""
    (row,) = record_remediation_plan(db_session, investigation.id, _plan())
    decide_recommendation(db_session, row.id, decision=ApprovalStatus.APPROVED, actor_id="a")

    with pytest.raises(ValueError, match="already approved"):
        decide_recommendation(db_session, row.id, decision=ApprovalStatus.REJECTED, actor_id="b")


def test_deciding_something_that_does_not_exist_fails_loudly(
    db_session: Session, investigation: Investigation
) -> None:
    from uuid import uuid4

    with pytest.raises(ValueError, match="no recommendation"):
        decide_recommendation(db_session, uuid4(), decision=ApprovalStatus.APPROVED, actor_id="a")


def test_mapping_is_pure_and_does_not_touch_the_session() -> None:
    from uuid import uuid4

    row = to_recommendation(uuid4(), _recommendation(), version=3)
    assert row.version == 3
    assert row.approval_status is ApprovalStatus.PENDING

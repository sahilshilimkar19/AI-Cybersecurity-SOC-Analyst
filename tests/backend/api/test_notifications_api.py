"""Tests for the notification history and retry endpoints.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise.

The assertion that matters most is a *negative* one: there is no route that
sends. Alerting is initiated by an approval at the human gate, and a send
endpoint would be a second entrance to the outbound path — one a client could
drive without a decision behind it.

Note what the fixtures cannot do any more: seed a notification with no approval.
The column is NOT NULL, so the row the old test asserted about is no longer
representable, which is a stronger result than any test could give.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from backend.app import create_app
from backend.db.orm.conversation import Conversation, HumanDecision
from backend.db.orm.investigation import Investigation
from backend.db.orm.notification import Notification
from backend.db.orm.user import User
from config.settings import Settings
from models.enums import (
    DecisionType,
    NotificationChannel,
    NotificationStatus,
    TriagePriority,
    TriggerSource,
    UserRole,
)


def _seed(db_engine: Engine, **overrides: Any) -> dict[str, str]:
    """Create an investigation, an approval, and one delivery record."""
    session = sessionmaker(bind=db_engine, expire_on_commit=False)()
    try:
        investigation = Investigation(
            trigger_source=TriggerSource.ALERT, title="notified case", pipeline={}
        )
        user = User(
            email=f"analyst-{uuid4().hex[:8]}@example.com",
            name="Approver",
            role=UserRole.SENIOR_ANALYST,
        )
        session.add_all([investigation, user])
        session.flush()

        conversation = Conversation(investigation_id=investigation.id)
        session.add(conversation)
        session.flush()
        approval = HumanDecision(
            conversation_id=conversation.id,
            user_id=user.id,
            decision=overrides.pop("decision", DecisionType.APPROVE),
        )
        session.add(approval)
        session.flush()

        payload: dict[str, Any] = {
            "investigation_id": investigation.id,
            "approval_id": approval.id,
            "channel": NotificationChannel.SLACK,
            "recipient": "#soc-alerts",
            "dedupe_key": uuid4().hex,
            "priority": TriagePriority.URGENT,
            "status": NotificationStatus.SENT,
            "delivery_attempts": 1,
            "sent_at": datetime.now(UTC),
        }
        payload.update(overrides)
        row = Notification(**payload)
        session.add(row)
        session.commit()
        return {
            "investigation_id": str(investigation.id),
            "approval_id": str(approval.id),
            "notification_id": str(row.id),
        }
    finally:
        session.close()


# --- Reading ----------------------------------------------------------------


def test_history_is_readable(client: TestClient, authenticate: Any, db_engine: Engine) -> None:
    _seed(db_engine)

    body = client.get("/notifications", headers=authenticate(UserRole.ANALYST)).json()
    assert body["total"] == 1
    assert body["items"][0]["channel"] == "slack"
    assert body["items"][0]["status"] == "sent"


def test_every_recorded_alert_names_the_decision_behind_it(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """The projection does not pretend an unapproved alert might exist."""
    seeded = _seed(db_engine)

    body = client.get("/notifications", headers=authenticate(UserRole.ANALYST)).json()
    assert body["items"][0]["approval_id"] == seeded["approval_id"]


def test_history_scopes_to_one_investigation(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    seeded = _seed(db_engine)
    _seed(db_engine)
    headers = authenticate(UserRole.ANALYST)

    scoped = client.get(
        f"/notifications?investigation_id={seeded['investigation_id']}", headers=headers
    ).json()
    assert scoped["total"] == 1

    unrelated = client.get(f"/notifications?investigation_id={uuid4()}", headers=headers).json()
    assert unrelated["total"] == 0


def test_history_filters_by_delivery_status(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    _seed(db_engine)
    _seed(db_engine, status=NotificationStatus.DEAD_LETTER, failure_reason="every channel failed")
    headers = authenticate(UserRole.ANALYST)

    dead = client.get("/notifications?status=dead_letter", headers=headers).json()
    assert dead["total"] == 1
    assert dead["items"][0]["failure_reason"] == "every channel failed"


def test_the_dead_letter_count_is_a_standing_fact_not_a_page_property(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """A queue of undelivered alerts is not a property of whichever rows you asked for."""
    _seed(db_engine, status=NotificationStatus.DEAD_LETTER, failure_reason="relay down")
    _seed(db_engine)

    body = client.get(
        "/notifications?status=sent&limit=1", headers=authenticate(UserRole.ANALYST)
    ).json()
    assert body["total"] == 1
    assert body["dead_lettered"] == 1


def test_a_failed_delivery_carries_its_reason(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """'It failed' is not a reason an operator can act on."""
    _seed(db_engine, status=NotificationStatus.FAILED, failure_reason="slack: channel_not_found")

    body = client.get("/notifications", headers=authenticate(UserRole.ANALYST)).json()
    assert "channel_not_found" in body["items"][0]["failure_reason"]


def test_history_requires_authentication(client: TestClient) -> None:
    assert client.get("/notifications").status_code == 401


# --- Retrying ---------------------------------------------------------------


def test_a_failed_delivery_can_be_retried_by_an_approver(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    seeded = _seed(db_engine, status=NotificationStatus.FAILED, failure_reason="relay down")

    response = client.post(
        f"/notifications/{seeded['notification_id']}/retry",
        headers=authenticate(UserRole.MANAGER),
    )
    assert response.status_code == 200
    body = response.json()
    # No channel is configured in the test app, so the retry is refused by the
    # adapter rather than delivered — which is the honest outcome, recorded.
    assert body["delivered"] is False
    assert body["status"] in {"failed", "dead_letter"}


def test_retrying_requires_the_capability_to_act_not_merely_to_look(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """A retry is a dispatch, so reading the history is not enough to trigger one."""
    seeded = _seed(db_engine, status=NotificationStatus.FAILED)

    response = client.post(
        f"/notifications/{seeded['notification_id']}/retry",
        headers=authenticate(UserRole.ANALYST),
    )
    assert response.status_code == 403


def test_an_auditor_may_read_history_but_not_retry(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    seeded = _seed(db_engine, status=NotificationStatus.FAILED)
    headers = authenticate(UserRole.AUDITOR)

    assert client.get("/notifications", headers=headers).status_code == 200
    assert (
        client.post(
            f"/notifications/{seeded['notification_id']}/retry", headers=headers
        ).status_code
        == 403
    )


def test_retrying_a_delivered_alert_is_refused(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """Sending it again is a new notification, and needs a new decision."""
    seeded = _seed(db_engine)

    response = client.post(
        f"/notifications/{seeded['notification_id']}/retry",
        headers=authenticate(UserRole.MANAGER),
    )
    assert response.status_code == 409
    assert "needs a new approval" in response.json()["message"]


def test_retrying_an_alert_whose_approval_was_withdrawn_is_refused(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """A retry is a fresh act, verified against the record as it now stands."""
    seeded = _seed(db_engine, status=NotificationStatus.FAILED, decision=DecisionType.REJECT)

    response = client.post(
        f"/notifications/{seeded['notification_id']}/retry",
        headers=authenticate(UserRole.MANAGER),
    )
    assert response.status_code == 409
    assert "not an approval" in response.json()["message"]


def test_retrying_something_that_does_not_exist_is_a_404(
    client: TestClient, authenticate: Any
) -> None:
    response = client.post(
        f"/notifications/{uuid4()}/retry", headers=authenticate(UserRole.MANAGER)
    )
    assert response.status_code == 404


# --- The absent send endpoint -----------------------------------------------


def test_no_route_can_originate_a_notification() -> None:
    """Alerting starts at the human gate. A send endpoint would be a second door.

    Read from the OpenAPI schema rather than by walking ``app.routes``: this
    FastAPI version keeps included routers wrapped rather than flattened, so
    walking the route list finds nothing and an assertion over it passes by
    being vacuous — which is the failure mode a security test can least afford.
    """
    app = create_app(Settings(log_json=False, log_level="WARNING"))
    paths = app.openapi()["paths"]
    assert any(path.startswith("/notifications") for path in paths), "routes not discoverable"

    mutating = {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
        if path.startswith("/notifications") and method.upper() not in {"GET", "HEAD", "OPTIONS"}
    }
    assert mutating == {("POST", "/notifications/{notification_id}/retry")}


@pytest.mark.parametrize("path", ["/notifications", "/notifications/send"])
def test_posting_an_alert_directly_is_not_possible(
    client: TestClient, authenticate: Any, path: str
) -> None:
    response = client.post(
        path,
        json={"channel": "slack", "recipient": "#soc", "body": "anything"},
        headers=authenticate(UserRole.ADMIN),
    )
    assert response.status_code in {404, 405}

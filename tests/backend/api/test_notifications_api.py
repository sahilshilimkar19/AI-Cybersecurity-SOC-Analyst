"""Tests for the notification history endpoint.

Read-only by construction. The assertion that matters most here is a *negative*
one: there is no route that sends. Dispatch lands with the controls built to
guard it, and until then the API cannot be used to bypass them.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from backend.app import create_app
from backend.db.orm.investigation import Investigation
from backend.db.orm.notification import Notification
from models.enums import (
    NotificationChannel,
    NotificationStatus,
    TriggerSource,
    UserRole,
)


def _seed_notification(db_engine: Engine, **overrides: Any) -> tuple[str, str]:
    session = sessionmaker(bind=db_engine, expire_on_commit=False)()
    try:
        investigation = Investigation(
            trigger_source=TriggerSource.ALERT, title="notified case", pipeline={}
        )
        session.add(investigation)
        session.flush()
        payload: dict[str, Any] = {
            "investigation_id": investigation.id,
            "channel": NotificationChannel.SLACK,
            "recipient": "#soc-alerts",
            "status": NotificationStatus.SENT,
            "delivery_attempts": 1,
            "sent_at": datetime.now(UTC),
        }
        payload.update(overrides)
        row = Notification(**payload)
        session.add(row)
        session.commit()
        return str(investigation.id), str(row.id)
    finally:
        session.close()


def test_history_is_readable(client: TestClient, authenticate: Any, db_engine: Engine) -> None:
    _seed_notification(db_engine)

    body = client.get("/notifications", headers=authenticate(UserRole.ANALYST)).json()
    assert body["total"] == 1
    assert body["items"][0]["channel"] == "slack"
    assert body["items"][0]["status"] == "sent"


def test_history_scopes_to_one_investigation(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    investigation_id, _ = _seed_notification(db_engine)
    _seed_notification(db_engine)
    headers = authenticate(UserRole.ANALYST)

    scoped = client.get(
        f"/notifications?investigation_id={investigation_id}", headers=headers
    ).json()
    assert scoped["total"] == 1

    unrelated = client.get(f"/notifications?investigation_id={uuid4()}", headers=headers).json()
    assert unrelated["total"] == 0


def test_an_unlinked_notification_shows_its_missing_approval(
    client: TestClient, authenticate: Any, db_engine: Engine
) -> None:
    """The absence of a linked approval is exactly what an auditor is looking for."""
    _seed_notification(db_engine, approval_id=None)

    body = client.get("/notifications", headers=authenticate(UserRole.AUDITOR)).json()
    assert body["items"][0]["approval_id"] is None


def test_history_requires_authentication(client: TestClient) -> None:
    assert client.get("/notifications").status_code == 401


def test_no_route_can_dispatch_a_notification() -> None:
    """Sending arrives with the post-approval controls built to guard it."""
    from config.settings import Settings

    app = create_app(Settings(log_json=False, log_level="WARNING"))
    notification_routes = {
        (method, getattr(route, "path", ""))
        for route in app.routes
        for method in getattr(route, "methods", set())
        if "notif" in getattr(route, "path", "")
    }
    assert all(method == "GET" for method, _ in notification_routes)

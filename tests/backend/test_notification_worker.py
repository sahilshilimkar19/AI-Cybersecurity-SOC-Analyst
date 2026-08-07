"""Tests for the background alert dispatcher.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise.

Dispatch runs behind the analyst's decision response, so nobody is watching when
it goes wrong. That makes its failure behavior the part worth testing: a
malformed payload is dropped rather than half-sent, an authority that does not
hold up is refused loudly, and neither takes the process down.

The authority test is the important one. The alert payload comes out of graph
state, which is derived from ingested log content — so the worker takes the
approval id from the caller's recorded decision and never from the payload. A
payload that tries to nominate its own authorization must not be able to.
"""

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.db.orm.conversation import Conversation, HumanDecision
from backend.db.orm.investigation import Investigation
from backend.db.orm.notification import Notification
from backend.db.orm.user import User
from backend.workers.notifications import deliver_alert
from config.settings import Settings
from integrations.notifications import SendResult
from models.enums import DecisionType, NotificationChannel, TriggerSource, UserRole
from tests.backend.test_notification_dispatch import RecordingChannel


@pytest.fixture
def factory(db_engine: Engine) -> Any:
    return sessionmaker(bind=db_engine, expire_on_commit=False)


def _settings(**overrides: Any) -> Settings:
    payload: dict[str, Any] = {
        "log_json": False,
        "log_level": "WARNING",
        "notification_channels": "slack",
        "slack_webhook_url": "https://hooks.slack.test/abc",
        "slack_channel": "#soc-alerts",
    }
    payload.update(overrides)
    return Settings(**payload)


def _approved_case(
    factory: Any, *, decision: DecisionType = DecisionType.APPROVE
) -> tuple[UUID, UUID]:
    session: Session = factory()
    try:
        investigation = Investigation(
            trigger_source=TriggerSource.ALERT, title="worker fixture", pipeline={}
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
            conversation_id=conversation.id, user_id=user.id, decision=decision
        )
        session.add(approval)
        session.commit()
        return UUID(str(investigation.id)), UUID(str(approval.id))
    finally:
        session.close()


def _payload(investigation_id: UUID, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "investigation_id": str(investigation_id),
        "title": "Investigation approved",
        "summary": "Credentials were guessed and used.",
        "priority": "urgent",
        "severity": "high",
        "verdict": "malicious",
        "highlights": ["Affected hosts: web-01"],
    }
    payload.update(overrides)
    return payload


def _notifications(factory: Any, investigation_id: UUID) -> list[Notification]:
    """The delivery rows for one investigation.

    Scoped rather than global: these tests commit, and the engine is
    session-scoped, so rows from earlier tests are still present. Asking about
    one investigation is also the more precise assertion — each test means "this
    case recorded nothing", not "the table is empty".
    """
    session: Session = factory()
    try:
        return list(
            session.execute(
                select(Notification).where(Notification.investigation_id == investigation_id)
            )
            .scalars()
            .all()
        )
    finally:
        session.close()


# --- The happy path ---------------------------------------------------------


def test_an_approved_alert_is_delivered_and_recorded(factory: Any) -> None:
    investigation_id, approval_id = _approved_case(factory)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        payload=_payload(investigation_id),
        approval_id=approval_id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert len(channel.sent) == 1
    (row,) = _notifications(factory, investigation_id)
    assert row.approval_id == approval_id


def test_the_console_link_reaches_the_message(factory: Any) -> None:
    investigation_id, approval_id = _approved_case(factory)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        payload=_payload(investigation_id),
        approval_id=approval_id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
        console_url="https://soc.example.com/investigations/abc",
    )

    assert "soc.example.com" in channel.sent[0][1]


# --- Authority --------------------------------------------------------------


def test_the_payload_cannot_nominate_its_own_authorization(factory: Any) -> None:
    """Graph state is derived from ingested content, which must not authorize itself."""
    investigation_id, approval_id = _approved_case(factory)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        # A hostile payload claiming an approval that does not exist.
        payload=_payload(investigation_id, approval_id=str(uuid4())),
        approval_id=approval_id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    (row,) = _notifications(factory, investigation_id)
    assert row.approval_id == approval_id


def test_an_authority_that_does_not_hold_up_sends_nothing(factory: Any) -> None:
    investigation_id, approval_id = _approved_case(factory, decision=DecisionType.REJECT)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        payload=_payload(investigation_id),
        approval_id=approval_id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert channel.sent == []
    assert _notifications(factory, investigation_id) == []


def test_a_fabricated_approval_sends_nothing(factory: Any) -> None:
    investigation_id, _ = _approved_case(factory)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        payload=_payload(investigation_id),
        approval_id=uuid4(),
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert channel.sent == []


# --- Degradation ------------------------------------------------------------


def test_a_malformed_payload_is_dropped_rather_than_half_sent(factory: Any) -> None:
    """A message missing the thing that made it urgent is worse than silence."""
    investigation_id, approval_id = _approved_case(factory)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        payload={"investigation_id": str(investigation_id), "title": "no summary"},
        approval_id=approval_id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert channel.sent == []
    assert _notifications(factory, investigation_id) == []


def test_a_channel_that_raises_does_not_take_the_worker_down(factory: Any) -> None:
    """Nobody is watching a background task; it must fail into the record."""
    investigation_id, approval_id = _approved_case(factory)

    class ExplodingChannel:
        @property
        def channel(self) -> NotificationChannel:
            return NotificationChannel.SLACK

        @property
        def is_available(self) -> bool:
            return True

        def send(self, *, recipient: str, message: Any) -> SendResult:
            raise RuntimeError("the webhook library exploded")

    deliver_alert(
        factory,
        payload=_payload(investigation_id),
        approval_id=approval_id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: ExplodingChannel()},
    )

    # The failed transaction is rolled back rather than half-written.
    assert _notifications(factory, investigation_id) == []


def test_an_unconfigured_deployment_records_nothing(factory: Any) -> None:
    investigation_id, approval_id = _approved_case(factory)

    deliver_alert(
        factory,
        payload=_payload(investigation_id),
        approval_id=approval_id,
        settings=Settings(log_json=False, log_level="WARNING"),
        channels={},
    )

    assert _notifications(factory, investigation_id) == []


def test_an_alert_below_the_floor_records_nothing(factory: Any) -> None:
    investigation_id, approval_id = _approved_case(factory)
    channel = RecordingChannel(NotificationChannel.SLACK)

    deliver_alert(
        factory,
        payload=_payload(investigation_id, priority="low"),
        approval_id=approval_id,
        settings=_settings(notification_min_priority="high"),
        channels={NotificationChannel.SLACK: channel},
    )

    assert channel.sent == []
    assert _notifications(factory, investigation_id) == []

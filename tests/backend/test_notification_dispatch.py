"""Tests for the dispatch service — the platform's only outbound write.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise.

The first section is the one the sprint exists for: nothing is sent without a
human approval that actually holds up. Carrying an id is not enough, so the tests
try the three ways an id can be present and worthless — fabricated, borrowed from
another investigation, and belonging to a decision that said *no*.

The rest cover the behavior an on-call team depends on: failover between
channels, idempotency under retry, a dead letter that is loud, and suppression
that is never mistaken for failure.
"""

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.orm.audit import AuditLog
from backend.db.orm.conversation import Conversation, HumanDecision
from backend.db.orm.investigation import Investigation
from backend.db.orm.notification import Notification
from backend.db.repositories.notification import NotificationRepository
from backend.services.notifications import (
    UnapprovedDispatchError,
    dispatch_alert,
    retry_delivery,
    verify_approval,
)
from config.settings import Settings
from integrations.notifications import NotificationChannelAdapter, SendResult
from models.enums import (
    DecisionType,
    NotificationChannel,
    NotificationStatus,
    TriagePriority,
    TriggerSource,
    UserRole,
)
from models.notification import AlertRequest


class RecordingChannel:
    """A channel that records what it was asked to send and answers as told."""

    def __init__(self, channel: NotificationChannel, *results: SendResult) -> None:
        self._channel = channel
        self._results = list(results) or [SendResult.ok()]
        self.sent: list[tuple[str, str]] = []

    @property
    def channel(self) -> NotificationChannel:
        return self._channel

    @property
    def is_available(self) -> bool:
        return True

    def send(self, *, recipient: str, message: Any) -> SendResult:
        self.sent.append((recipient, message.body))
        return self._results.pop(0) if len(self._results) > 1 else self._results[0]


def _settings(**overrides: Any) -> Settings:
    payload: dict[str, Any] = {
        "log_json": False,
        "log_level": "WARNING",
        "notification_channels": "slack",
        "slack_webhook_url": "https://hooks.slack.test/abc",
        "slack_channel": "#soc-alerts",
        "notification_retry_seconds": 0.0001,
    }
    payload.update(overrides)
    return Settings(**payload)


def _both_channels(**overrides: Any) -> Settings:
    return _settings(
        notification_channels="slack,email",
        smtp_host="smtp.test",
        smtp_from_address="soc@example.com",
        smtp_recipients="oncall@example.com",
        **overrides,
    )


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    row = Investigation(trigger_source=TriggerSource.ALERT, title="dispatch fixture", pipeline={})
    db_session.add(row)
    db_session.flush()
    return row


def _decision(
    db_session: Session,
    investigation: Investigation,
    *,
    decision: DecisionType = DecisionType.APPROVE,
) -> HumanDecision:
    from backend.db.orm.user import User

    user = User(
        email=f"analyst-{uuid4().hex[:8]}@example.com",
        name="Test Analyst",
        role=UserRole.SENIOR_ANALYST,
    )
    conversation = Conversation(investigation_id=investigation.id)
    db_session.add_all([user, conversation])
    db_session.flush()

    row = HumanDecision(conversation_id=conversation.id, user_id=user.id, decision=decision)
    db_session.add(row)
    db_session.flush()
    return row


def _alert(investigation: Investigation, approval_id: UUID, **overrides: Any) -> AlertRequest:
    payload: dict[str, Any] = {
        "investigation_id": investigation.id,
        "approval_id": approval_id,
        "title": "Approved investigation",
        "summary": "Credentials were guessed and used.",
        "priority": TriagePriority.URGENT,
    }
    payload.update(overrides)
    return AlertRequest(**payload)


# --- No dispatch without a verified approval --------------------------------


def test_a_fabricated_approval_id_is_refused(
    db_session: Session, investigation: Investigation
) -> None:
    """Carrying an id is not the same as having an approval."""
    with pytest.raises(UnapprovedDispatchError, match="no human decision"):
        verify_approval(db_session, investigation_id=investigation.id, approval_id=uuid4())


def test_an_approval_borrowed_from_another_investigation_is_refused(
    db_session: Session, investigation: Investigation
) -> None:
    """Someone did approve something — just not this."""
    other = Investigation(trigger_source=TriggerSource.ALERT, title="other", pipeline={})
    db_session.add(other)
    db_session.flush()
    approval = _decision(db_session, other)

    with pytest.raises(UnapprovedDispatchError, match="does not belong"):
        verify_approval(db_session, investigation_id=investigation.id, approval_id=approval.id)


@pytest.mark.parametrize(
    "decision", [DecisionType.REJECT, DecisionType.EDIT, DecisionType.REDIRECT]
)
def test_only_an_approval_authorizes_an_alert(
    db_session: Session, investigation: Investigation, decision: DecisionType
) -> None:
    """Paging an on-call engineer about findings an analyst rejected is worse than silence."""
    recorded = _decision(db_session, investigation, decision=decision)

    with pytest.raises(UnapprovedDispatchError, match="not an approval"):
        verify_approval(db_session, investigation_id=investigation.id, approval_id=recorded.id)


def test_dispatch_refuses_before_touching_a_channel(
    db_session: Session, investigation: Investigation
) -> None:
    """The guard runs first, so an unapproved alert never reaches an adapter."""
    channel = RecordingChannel(NotificationChannel.SLACK)
    rejected = _decision(db_session, investigation, decision=DecisionType.REJECT)

    with pytest.raises(UnapprovedDispatchError):
        dispatch_alert(
            db_session,
            alert=_alert(investigation, rejected.id),
            settings=_settings(),
            channels={NotificationChannel.SLACK: channel},
        )
    assert channel.sent == []


def test_a_refused_dispatch_writes_no_delivery_row(
    db_session: Session, investigation: Investigation
) -> None:
    rejected = _decision(db_session, investigation, decision=DecisionType.REJECT)

    with pytest.raises(UnapprovedDispatchError):
        dispatch_alert(
            db_session,
            alert=_alert(investigation, rejected.id),
            settings=_settings(),
            channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
        )
    assert db_session.execute(select(Notification)).scalars().all() == []


# --- Delivery ---------------------------------------------------------------


def test_an_approved_alert_is_delivered_and_recorded(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)
    channel = RecordingChannel(NotificationChannel.SLACK)

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert result.delivered is True
    assert channel.sent[0][0] == "#soc-alerts"

    (row,) = db_session.execute(select(Notification)).scalars().all()
    assert row.status is NotificationStatus.SENT
    assert row.approval_id == approval.id
    assert row.sent_at is not None
    assert row.failure_reason is None


def test_every_delivery_row_names_the_decision_behind_it(
    db_session: Session, investigation: Investigation
) -> None:
    """The column is NOT NULL, so this is a shape rather than a convention."""
    approval = _decision(db_session, investigation)
    dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(),
        channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
    )

    rows = db_session.execute(select(Notification)).scalars().all()
    assert all(row.approval_id is not None for row in rows)


def test_a_transient_failure_is_retried_on_the_same_channel(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)
    channel = RecordingChannel(NotificationChannel.SLACK, SendResult.failed("503"), SendResult.ok())

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(notification_max_attempts=3),
        channels={NotificationChannel.SLACK: channel},
        sleep=lambda _seconds: None,
    )

    assert result.delivered is True
    assert result.outcomes[0].attempts == 2


def test_a_refusal_is_not_retried_on_the_same_channel(
    db_session: Session, investigation: Investigation
) -> None:
    """An open circuit will not have changed in two seconds; fail over instead."""
    approval = _decision(db_session, investigation)
    channel = RecordingChannel(NotificationChannel.SLACK, SendResult.refuse("circuit is open"))

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(notification_max_attempts=3),
        channels={NotificationChannel.SLACK: channel},
        sleep=lambda _seconds: None,
    )

    assert result.outcomes[0].attempts == 1


# --- Failover ---------------------------------------------------------------


def test_slack_failure_falls_over_to_email(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)
    slack = RecordingChannel(NotificationChannel.SLACK, SendResult.failed("slack is down"))
    email = RecordingChannel(NotificationChannel.EMAIL)

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_both_channels(notification_max_attempts=1),
        channels={NotificationChannel.SLACK: slack, NotificationChannel.EMAIL: email},
        sleep=lambda _seconds: None,
    )

    assert result.delivered is True
    assert result.failed_over is True
    assert email.sent[0][0] == "oncall@example.com"


def test_a_successful_first_channel_is_not_followed_by_a_duplicate_page(
    db_session: Session, investigation: Investigation
) -> None:
    """Failover is a fallback, not a fan-out."""
    approval = _decision(db_session, investigation)
    email = RecordingChannel(NotificationChannel.EMAIL)

    dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_both_channels(),
        channels={
            NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK),
            NotificationChannel.EMAIL: email,
        },
    )

    assert email.sent == []


def test_a_channel_with_no_adapter_is_recorded_rather_than_skipped(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(),
        channels={},
    )

    assert result.delivered is False
    assert result.outcomes[0].refused is True


# --- Dead letter ------------------------------------------------------------


def test_every_channel_failing_dead_letters_loudly(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_both_channels(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("slack down")
            ),
            NotificationChannel.EMAIL: RecordingChannel(
                NotificationChannel.EMAIL, SendResult.failed("relay down")
            ),
        },
        sleep=lambda _seconds: None,
    )

    assert result.dead_lettered is True
    assert result.delivered is False

    rows = db_session.execute(select(Notification)).scalars().all()
    assert all(row.status is NotificationStatus.DEAD_LETTER for row in rows)
    assert all(row.failure_reason for row in rows)


def test_a_dead_letter_is_written_to_the_audit_trail(
    db_session: Session, investigation: Investigation
) -> None:
    """The ops alert is a record, not another notification down the failed channels."""
    approval = _decision(db_session, investigation)
    dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("slack down")
            )
        },
        sleep=lambda _seconds: None,
    )

    actions = set(db_session.execute(select(AuditLog.action)).scalars().all())
    assert "notification.dead_letter" in actions


def test_a_dead_letter_records_why_each_channel_failed(
    db_session: Session, investigation: Investigation
) -> None:
    """'It failed' is not a reason an operator can act on."""
    approval = _decision(db_session, investigation)
    dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("channel_not_found")
            )
        },
        sleep=lambda _seconds: None,
    )

    entry = (
        db_session.execute(select(AuditLog).where(AuditLog.action == "notification.dead_letter"))
        .scalars()
        .one()
    )
    assert "channel_not_found" in (entry.after_ref or "")


def test_a_dead_letter_is_visible_in_the_queue(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)
    dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("down")
            )
        },
        sleep=lambda _seconds: None,
    )

    assert len(NotificationRepository(db_session).dead_lettered()) == 1


# --- Suppression is not failure ---------------------------------------------


def test_below_the_floor_nothing_is_sent_and_nothing_is_recorded(
    db_session: Session, investigation: Investigation
) -> None:
    """Nobody was told because nobody needed to be."""
    approval = _decision(db_session, investigation)
    channel = RecordingChannel(NotificationChannel.SLACK)

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id, priority=TriagePriority.LOW),
        settings=_settings(notification_min_priority="high"),
        channels={NotificationChannel.SLACK: channel},
    )

    assert channel.sent == []
    assert result.attempted is False
    assert result.dead_lettered is False
    assert result.no_channel_configured is False
    assert db_session.execute(select(Notification)).scalars().all() == []


def test_no_channel_configured_is_reported_as_itself(
    db_session: Session, investigation: Investigation
) -> None:
    """A deployment choice, distinguished from every channel having failed."""
    approval = _decision(db_session, investigation)

    result = dispatch_alert(
        db_session,
        alert=_alert(investigation, approval.id),
        settings=Settings(log_json=False, log_level="WARNING"),
        channels={},
    )

    assert result.no_channel_configured is True
    assert result.dead_lettered is False
    assert result.attempted is False


# --- Idempotency ------------------------------------------------------------


def test_dispatching_the_same_approval_twice_sends_once(
    db_session: Session, investigation: Investigation
) -> None:
    """A retried request must not become a second page at 3am."""
    approval = _decision(db_session, investigation)
    channel = RecordingChannel(NotificationChannel.SLACK)
    alert = _alert(investigation, approval.id)

    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )
    second = dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert len(channel.sent) == 1
    assert second.deduplicated
    assert len(db_session.execute(select(Notification)).scalars().all()) == 1


def test_a_new_decision_may_alert_again(db_session: Session, investigation: Investigation) -> None:
    """After a redirect and a second review, the case can page again."""
    channel = RecordingChannel(NotificationChannel.SLACK)
    first = _decision(db_session, investigation)
    dispatch_alert(
        db_session,
        alert=_alert(investigation, first.id),
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    second = _decision(db_session, investigation)
    dispatch_alert(
        db_session,
        alert=_alert(investigation, second.id),
        settings=_settings(),
        channels={NotificationChannel.SLACK: channel},
    )

    assert len(channel.sent) == 2


def test_a_failed_delivery_is_retried_rather_than_deduplicated(
    db_session: Session, investigation: Investigation
) -> None:
    """Dedupe protects the recipient from repeats, not the alert from arriving."""
    approval = _decision(db_session, investigation)
    alert = _alert(investigation, approval.id)
    failing = RecordingChannel(NotificationChannel.SLACK, SendResult.failed("down"))

    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(notification_max_attempts=1),
        channels={NotificationChannel.SLACK: failing},
        sleep=lambda _seconds: None,
    )
    recovered = RecordingChannel(NotificationChannel.SLACK)
    result = dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(notification_max_attempts=1),
        channels={NotificationChannel.SLACK: recovered},
    )

    assert result.delivered is True
    assert len(db_session.execute(select(Notification)).scalars().all()) == 1


# --- Retrying one delivery --------------------------------------------------


def test_a_failed_delivery_can_be_retried_on_its_original_authority(
    db_session: Session, investigation: Investigation
) -> None:
    approval = _decision(db_session, investigation)
    alert = _alert(investigation, approval.id)
    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("down")
            )
        },
        sleep=lambda _seconds: None,
    )
    (row,) = db_session.execute(select(Notification)).scalars().all()

    outcome = retry_delivery(
        db_session,
        notification_id=row.id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
        alert=alert,
    )

    assert outcome.delivered is True
    db_session.refresh(row)
    assert row.status is NotificationStatus.SENT


def test_retrying_a_delivered_alert_is_refused(
    db_session: Session, investigation: Investigation
) -> None:
    """Sending it again is a new notification, and needs a new decision."""
    approval = _decision(db_session, investigation)
    alert = _alert(investigation, approval.id)
    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(),
        channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
    )
    (row,) = db_session.execute(select(Notification)).scalars().all()

    with pytest.raises(UnapprovedDispatchError, match="already delivered"):
        retry_delivery(
            db_session,
            notification_id=row.id,
            settings=_settings(),
            channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
            alert=alert,
        )


def test_retrying_something_that_does_not_exist_fails_loudly(
    db_session: Session, investigation: Investigation
) -> None:
    with pytest.raises(UnapprovedDispatchError, match="no notification"):
        retry_delivery(
            db_session,
            notification_id=uuid4(),
            settings=_settings(),
            channels={},
            alert=_alert(investigation, uuid4()),
        )


def test_a_failed_retry_leaves_a_dead_letter_dead_lettered(
    db_session: Session, investigation: Investigation
) -> None:
    """A failed retry must not promote a dead letter back to merely-failed."""
    approval = _decision(db_session, investigation)
    alert = _alert(investigation, approval.id)
    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("down")
            )
        },
        sleep=lambda _seconds: None,
    )
    (row,) = db_session.execute(select(Notification)).scalars().all()
    assert row.status is NotificationStatus.DEAD_LETTER

    retry_delivery(
        db_session,
        notification_id=row.id,
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("still down")
            )
        },
        alert=alert,
        sleep=lambda _seconds: None,
    )

    db_session.refresh(row)
    assert row.status is NotificationStatus.DEAD_LETTER


def test_a_retry_is_audited(db_session: Session, investigation: Investigation) -> None:
    approval = _decision(db_session, investigation)
    alert = _alert(investigation, approval.id)
    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("down")
            )
        },
        sleep=lambda _seconds: None,
    )
    (row,) = db_session.execute(select(Notification)).scalars().all()

    retry_delivery(
        db_session,
        notification_id=row.id,
        settings=_settings(),
        channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
        alert=alert,
    )

    actions = set(db_session.execute(select(AuditLog.action)).scalars().all())
    assert "notification.retried" in actions


def test_a_retry_re_verifies_the_approval_rather_than_trusting_the_row(
    db_session: Session, investigation: Investigation
) -> None:
    """The row was written by an earlier request; a retry is a fresh act."""
    approval = _decision(db_session, investigation)
    alert = _alert(investigation, approval.id)
    dispatch_alert(
        db_session,
        alert=alert,
        settings=_settings(notification_max_attempts=1),
        channels={
            NotificationChannel.SLACK: RecordingChannel(
                NotificationChannel.SLACK, SendResult.failed("down")
            )
        },
        sleep=lambda _seconds: None,
    )
    (row,) = db_session.execute(select(Notification)).scalars().all()

    # The decision is downgraded after the fact — the retry must notice.
    approval.decision = DecisionType.REJECT
    db_session.flush()

    with pytest.raises(UnapprovedDispatchError, match="not an approval"):
        retry_delivery(
            db_session,
            notification_id=row.id,
            settings=_settings(),
            channels={NotificationChannel.SLACK: RecordingChannel(NotificationChannel.SLACK)},
            alert=alert,
        )


# --- Adapter typing ---------------------------------------------------------


def test_the_recording_channel_satisfies_the_adapter_protocol() -> None:
    """Keeps the test double honest about the interface it stands in for."""
    adapter: NotificationChannelAdapter = RecordingChannel(NotificationChannel.SLACK)
    assert adapter.channel is NotificationChannel.SLACK

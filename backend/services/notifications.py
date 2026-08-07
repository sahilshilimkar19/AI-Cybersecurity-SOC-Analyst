"""Dispatching approved alerts (invariants #1, #6, #7).

The one place in the platform where a machine acts on the outside world. Every
guard that matters is here, at the write boundary, rather than distributed across
the adapters — one enforcement point can be read and tested; five can be four
correct ones and a hole.

**Nothing is sent without a verified human approval.** Carrying an ``approval_id``
is not enough: this looks the decision up, confirms it belongs to *this*
investigation, and confirms it was an approval rather than a rejection or a
redirect. The required field stops the accident; the lookup stops the forgery.

**Failover is between channels, never within one.** Every recipient on a channel
is attempted, because three on-call addresses are three people who each need the
message. The next channel is tried only when the previous one reached nobody —
which is what makes Slack→email a fallback rather than a second page.

**Nothing fails silently.** When every channel fails, the last delivery is marked
dead-letter, an audit entry is written, and an error is logged. The ops alert is
deliberately *not* another notification: the channels just proved they cannot
deliver, and routing the failure through them would be a joke at the expense of
whoever needed to know.

**Suppression is not failure.** An investigation below the alerting floor, or a
deployment with no channel configured, produces no delivery and says exactly
that. Reporting either as a failure is how a team learns to ignore its own
dead-letter queue.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from backend.db.orm.conversation import Conversation, HumanDecision
from backend.db.orm.notification import Notification
from backend.db.repositories.audit import AuditLogRepository
from backend.db.repositories.notification import NotificationRepository
from config.logging import get_logger
from integrations.notifications import NotificationChannelAdapter, SendResult
from models.enums import DecisionType, NotificationChannel, NotificationStatus
from models.notification import AlertRequest, AlertTarget, DeliveryOutcome, DispatchResult
from services.notifications import dedupe_key, failover_plan, is_worth_alerting, resolve_targets
from tools.notifications import render

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from sqlalchemy.orm import Session

    from config.settings import Settings

_logger = get_logger(__name__)


class UnapprovedDispatchError(Exception):
    """An alert was submitted without a valid human approval behind it.

    Raised rather than returned. A caller that forgot the approval has a bug, and
    a bug in the one guard standing between an assistive platform and an
    autonomous one should stop the request rather than degrade it.
    """


def verify_approval(
    session: Session, *, investigation_id: UUID, approval_id: UUID
) -> HumanDecision:
    """Load the human decision authorizing an alert, or refuse.

    Three separate things are checked, because each has its own way of going
    wrong: the decision has to exist (not a fabricated id), it has to belong to
    this investigation (not borrowed from another case someone did approve), and
    it has to be an approval (not the rejection that says *do not* tell anyone).
    """
    decision = session.get(HumanDecision, approval_id)
    if decision is None:
        raise UnapprovedDispatchError(f"no human decision {approval_id}")

    conversation = session.get(Conversation, decision.conversation_id)
    if conversation is None or conversation.investigation_id != investigation_id:
        raise UnapprovedDispatchError(
            f"decision {approval_id} does not belong to investigation {investigation_id}"
        )
    if decision.decision is not DecisionType.APPROVE:
        raise UnapprovedDispatchError(
            f"decision {approval_id} was {decision.decision.value}, not an approval; "
            "an alert may only follow an approval"
        )
    return decision


def dispatch_alert(
    session: Session,
    *,
    alert: AlertRequest,
    settings: Settings,
    channels: Mapping[NotificationChannel, NotificationChannelAdapter],
    actor_id: UUID | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> DispatchResult:
    """Deliver one approved alert across the configured channels."""
    verify_approval(session, investigation_id=alert.investigation_id, approval_id=alert.approval_id)

    result = DispatchResult(investigation_id=alert.investigation_id, approval_id=alert.approval_id)

    if not is_worth_alerting(alert.priority, minimum=settings.notification_min_priority):
        _logger.info(
            "notification_suppressed_below_threshold",
            investigation_id=str(alert.investigation_id),
            priority=alert.priority.value,
            minimum=settings.notification_min_priority.value,
        )
        return result

    targets = resolve_targets(settings)
    if not targets:
        _logger.warning(
            "notification_no_channel_configured",
            investigation_id=str(alert.investigation_id),
        )
        return result.model_copy(update={"no_channel_configured": True})

    outcomes: list[DeliveryOutcome] = []
    deduplicated: list[AlertTarget] = []
    delivered_anywhere = False

    for tier in failover_plan(targets):
        if delivered_anywhere:
            # A previous channel reached someone. Sending again on the fallback
            # would be a duplicate page, not a failover.
            break
        for target in tier:
            outcome = _deliver(
                session,
                alert=alert,
                target=target,
                adapter=channels.get(target.channel),
                settings=settings,
                sleep=sleep,
                already_sent=deduplicated,
            )
            if outcome is None:
                continue
            outcomes.append(outcome)
            delivered_anywhere = delivered_anywhere or outcome.delivered

    result = result.model_copy(update={"outcomes": outcomes, "deduplicated": deduplicated})

    if outcomes and not delivered_anywhere:
        _dead_letter(session, alert=alert, outcomes=outcomes, actor_id=actor_id)
        result = result.model_copy(update={"dead_lettered": True})

    _logger.info(
        "notification_dispatch_complete",
        investigation_id=str(alert.investigation_id),
        approval_id=str(alert.approval_id),
        attempted=len(outcomes),
        delivered=result.delivered,
        failed_over=result.failed_over,
        dead_lettered=result.dead_lettered,
        deduplicated=len(deduplicated),
    )
    return result


def _deliver(
    session: Session,
    *,
    alert: AlertRequest,
    target: AlertTarget,
    adapter: NotificationChannelAdapter | None,
    settings: Settings,
    sleep: Callable[[float], None],
    already_sent: list[AlertTarget],
) -> DeliveryOutcome | None:
    """Attempt one target, creating or updating its delivery record.

    Returns ``None`` when the delivery was deduplicated — an alert already sent
    for this approval on this target is not attempted again, because the
    recipient has it and a second copy is noise at exactly the moment nobody can
    afford noise.
    """
    repository = NotificationRepository(session)
    key = dedupe_key(
        investigation_id=alert.investigation_id,
        approval_id=alert.approval_id,
        channel=target.channel,
        recipient=target.recipient,
    )

    row = repository.by_dedupe_key(key)
    if row is not None and row.status is NotificationStatus.SENT:
        already_sent.append(target)
        _logger.info(
            "notification_deduplicated",
            investigation_id=str(alert.investigation_id),
            channel=target.channel.value,
        )
        return None

    if row is None:
        row = Notification(
            investigation_id=alert.investigation_id,
            approval_id=alert.approval_id,
            channel=target.channel,
            recipient=target.recipient,
            dedupe_key=key,
            priority=alert.priority,
            status=NotificationStatus.PENDING,
        )
        session.add(row)
        session.flush()

    message = render(alert, target.channel)
    attempts = 0
    result = SendResult.refuse(f"{target.channel.value} has no adapter configured")

    if adapter is not None:
        for attempt in range(1, settings.notification_max_attempts + 1):
            result = adapter.send(recipient=target.recipient, message=message)
            attempts = attempt
            if result.delivered or result.refused:
                # A refusal is not retried on the same channel: an open circuit
                # or an exhausted budget will not have changed in two seconds,
                # and retrying into it only delays the failover that will work.
                break
            if attempt < settings.notification_max_attempts:
                sleep(settings.notification_retry_seconds)

    row.delivery_attempts += attempts
    if result.delivered:
        row.status = NotificationStatus.SENT
        row.sent_at = datetime.now(UTC)
        row.failure_reason = None
    else:
        row.status = NotificationStatus.FAILED
        row.failure_reason = result.detail[:500]
    session.flush()

    _logger.info(
        "notification_delivery_attempted",
        investigation_id=str(alert.investigation_id),
        channel=target.channel.value,
        delivered=result.delivered,
        refused=result.refused,
        attempts=attempts,
    )
    return DeliveryOutcome(
        channel=target.channel,
        recipient=target.recipient,
        delivered=result.delivered,
        attempts=attempts,
        detail=result.detail,
        refused=result.refused,
    )


def _dead_letter(
    session: Session,
    *,
    alert: AlertRequest,
    outcomes: Sequence[DeliveryOutcome],
    actor_id: UUID | None,
) -> None:
    """Record that an approved alert reached nobody.

    The ops alert is an audit entry and an error log, not another notification.
    Every configured channel has just demonstrated it cannot deliver; routing the
    news of that through the same channels would be a joke at the expense of
    whoever needed to know. Making the failure loud *in the record* is what an
    operator can actually act on.
    """
    repository = NotificationRepository(session)
    reasons = "; ".join(
        f"{outcome.channel.value}: {outcome.detail}" for outcome in outcomes if outcome.detail
    )

    for row in repository.for_approval(alert.approval_id):
        if row.status is NotificationStatus.FAILED:
            row.status = NotificationStatus.DEAD_LETTER
    session.flush()

    AuditLogRepository(session).append(
        action="notification.dead_letter",
        entity_type="investigation",
        entity_id=alert.investigation_id,
        actor_id=actor_id,
        after_ref=reasons[:1024] or "every configured channel failed",
    )
    _logger.error(
        "notification_dead_lettered",
        investigation_id=str(alert.investigation_id),
        approval_id=str(alert.approval_id),
        channels=[outcome.channel.value for outcome in outcomes],
        reasons=reasons[:500],
    )


def retry_delivery(
    session: Session,
    *,
    notification_id: UUID,
    settings: Settings,
    channels: Mapping[NotificationChannel, NotificationChannelAdapter],
    alert: AlertRequest,
    actor_id: UUID | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> DeliveryOutcome:
    """Re-attempt one failed delivery on its original channel and authority.

    Deliberately narrow. This retries a delivery that *failed*; it is not a way
    to re-send an alert someone already received, which would be a new
    notification and would therefore need a new human decision. The approval is
    re-verified rather than trusted from the row, because the row was written by
    an earlier request and this is a fresh act.
    """
    row = session.get(Notification, notification_id)
    if row is None:
        raise UnapprovedDispatchError(f"no notification {notification_id}")
    if row.status is NotificationStatus.SENT:
        raise UnapprovedDispatchError(
            "this alert was already delivered; sending it again is a new notification "
            "and needs a new approval"
        )

    verify_approval(session, investigation_id=row.investigation_id, approval_id=row.approval_id)

    adapter = channels.get(row.channel)
    message = render(alert, row.channel)
    attempts = 0
    result = SendResult.refuse(f"{row.channel.value} has no adapter configured")

    if adapter is not None:
        for attempt in range(1, settings.notification_max_attempts + 1):
            result = adapter.send(recipient=row.recipient, message=message)
            attempts = attempt
            if result.delivered or result.refused:
                break
            if attempt < settings.notification_max_attempts:
                sleep(settings.notification_retry_seconds)

    row.delivery_attempts += attempts
    if result.delivered:
        row.status = NotificationStatus.SENT
        row.sent_at = datetime.now(UTC)
        row.failure_reason = None
    else:
        # Stays dead-lettered if it already was: a failed retry does not promote
        # a dead letter back to a merely-failed delivery.
        row.status = (
            NotificationStatus.DEAD_LETTER
            if row.status is NotificationStatus.DEAD_LETTER
            else NotificationStatus.FAILED
        )
        row.failure_reason = result.detail[:500]
    session.flush()

    AuditLogRepository(session).append(
        action="notification.retried",
        entity_type="notification",
        entity_id=notification_id,
        actor_id=actor_id,
        after_ref=f"delivered={result.delivered}",
    )
    _logger.info(
        "notification_retry",
        notification_id=str(notification_id),
        channel=row.channel.value,
        delivered=result.delivered,
        attempts=attempts,
    )
    return DeliveryOutcome(
        channel=row.channel,
        recipient=row.recipient,
        delivered=result.delivered,
        attempts=attempts,
        detail=result.detail,
        refused=result.refused,
    )

"""Notification history and delivery retry.

Note what is not here: no endpoint sends an alert. Alerting is initiated by an
approval at the human gate, and a send endpoint would be a second entrance to the
outbound path — one that a client could drive without a decision behind it. The
design depends on there being exactly one entrance, so a test asserts that the
only mutating route in this module is the retry below.

Retrying is deliberately narrow. It re-attempts a delivery that **failed**, on
the channel and the human authority already recorded, and it refuses a delivery
that already succeeded: re-sending an alert someone has is a new notification,
and a new notification needs a new decision (invariant #1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.api.deps import (
    get_db,
    get_notification_channels,
    get_settings_dep,
    require_capability,
)
from backend.api.errors import ConflictError, NotFoundError
from backend.api.schemas.notifications import NotificationPage, NotificationView, RetryResponse
from backend.auth.rbac import Capability
from backend.auth.schemas import Principal
from backend.db.orm.investigation import Investigation
from backend.db.orm.notification import Notification
from backend.db.repositories.audit import AuditLogRepository
from backend.db.repositories.notification import NotificationRepository
from backend.services.notifications import UnapprovedDispatchError, retry_delivery
from config.settings import Settings
from models.enums import NotificationStatus
from models.notification import AlertRequest

if TYPE_CHECKING:
    from integrations.notifications import NotificationChannelAdapter
    from models.enums import NotificationChannel

router = APIRouter(prefix="/notifications", tags=["notifications"])

_view = Depends(require_capability(Capability.VIEW_INVESTIGATIONS))
# Retrying is a dispatch, so it needs the capability that authorizes acting —
# not the one that authorizes looking.
_approve = Depends(require_capability(Capability.APPROVE_ACTIONS))


@router.get("", response_model=NotificationPage)
def list_notifications(
    principal: Principal = _view,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    investigation_id: UUID | None = None,
    status: NotificationStatus | None = None,
    limit: int | None = Query(default=None, ge=1),
    offset: int = Query(default=0, ge=0),
) -> NotificationPage:
    """Notification history, newest first, optionally scoped or filtered."""
    size = min(limit or settings.investigation_page_size, settings.investigation_page_size_max)
    repository = NotificationRepository(db)
    rows, total = repository.page(
        limit=size, offset=offset, investigation_id=investigation_id, status=status
    )
    return NotificationPage(
        items=[NotificationView.model_validate(row, from_attributes=True) for row in rows],
        total=total,
        limit=size,
        offset=offset,
        dead_lettered=repository.count_by_status(NotificationStatus.DEAD_LETTER),
    )


@router.post("/{notification_id}/retry", response_model=RetryResponse)
def retry_notification(
    notification_id: UUID,
    request: Request,
    principal: Principal = _approve,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    channels: dict[NotificationChannel, NotificationChannelAdapter] = Depends(
        get_notification_channels
    ),
) -> RetryResponse:
    """Re-attempt one failed delivery on its original channel and authority.

    Runs inline rather than in the background: a person clicked retry and is
    waiting to find out whether it worked, which is the opposite of the automatic
    dispatch case where nobody is watching.
    """
    row = db.get(Notification, notification_id)
    if row is None:
        raise NotFoundError("no such notification")

    alert = _rebuild_alert(db, row)
    try:
        outcome = retry_delivery(
            db,
            notification_id=notification_id,
            settings=settings,
            channels=channels,
            alert=alert,
            actor_id=principal.user_id,
        )
    except UnapprovedDispatchError as exc:
        raise ConflictError(str(exc)) from exc

    AuditLogRepository(db).append(
        action="notification.retry_requested",
        entity_type="notification",
        entity_id=notification_id,
        actor_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
    db.flush()
    db.refresh(row)
    return RetryResponse(
        notification_id=notification_id,
        channel=outcome.channel,
        delivered=outcome.delivered,
        attempts=outcome.attempts,
        detail=outcome.detail,
        status=row.status,
    )


def _rebuild_alert(session: Session, row: Notification) -> AlertRequest:
    """Reconstruct the alert for a retry from the record, not from a client body.

    A retry must send the same thing the approval authorized. Accepting content
    from the caller would turn "resend what was approved" into "send whatever you
    like on the authority of something that was approved" — which is the exact
    substitution the gate exists to prevent.
    """
    investigation = session.get(Investigation, row.investigation_id)
    title = (
        investigation.title
        if investigation is not None and investigation.title
        else f"Investigation {row.investigation_id}"
    )
    summary = (
        investigation.summary
        if investigation is not None and investigation.summary
        else "An analyst approved this investigation; see the console for detail."
    )
    return AlertRequest(
        investigation_id=row.investigation_id,
        approval_id=row.approval_id,
        title=title,
        summary=summary,
        priority=row.priority,
        severity=investigation.severity if investigation is not None else None,
    )

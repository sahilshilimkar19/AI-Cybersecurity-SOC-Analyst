"""Notification history — read-only.

There is deliberately no send endpoint here. Dispatch arrives with the
Notifications sprint, together with the post-approval enforcement, dedupe, and
failover built to guard it; shipping a way to send ahead of the controls on
sending would be exactly the wrong order.

What exists now is the record an alert leaves behind, and the screen that reads
it — including, importantly, whether each one was linked to a human approval.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.deps import get_db, get_settings_dep, require_capability
from backend.api.schemas.notifications import NotificationPage, NotificationView
from backend.auth.rbac import Capability
from backend.auth.schemas import Principal
from backend.db.orm.notification import Notification
from config.settings import Settings

router = APIRouter(prefix="/notifications", tags=["notifications"])

_view = Depends(require_capability(Capability.VIEW_INVESTIGATIONS))


@router.get("", response_model=NotificationPage)
def list_notifications(
    principal: Principal = _view,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    investigation_id: UUID | None = None,
    limit: int | None = Query(default=None, ge=1),
    offset: int = Query(default=0, ge=0),
) -> NotificationPage:
    """Notification history, newest first, optionally scoped to one investigation."""
    size = min(limit or settings.investigation_page_size, settings.investigation_page_size_max)
    conditions = []
    if investigation_id is not None:
        conditions.append(Notification.investigation_id == investigation_id)

    total = db.execute(
        select(func.count()).select_from(Notification).where(*conditions)
    ).scalar_one()
    rows = (
        db.execute(
            select(Notification)
            .where(*conditions)
            .order_by(Notification.created_at.desc(), Notification.id.desc())
            .limit(size)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return NotificationPage(
        items=[NotificationView.model_validate(row, from_attributes=True) for row in rows],
        total=int(total),
        limit=size,
        offset=offset,
    )

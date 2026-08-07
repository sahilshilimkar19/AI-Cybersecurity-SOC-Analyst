"""Delivering an approved alert, off the request path.

Dispatch is network work against someone else's infrastructure: a Slack webhook
can be slow, and an SMTP relay can hang until a timeout. Holding the analyst's
decision request open for that would make approving feel broken exactly when the
platform most needs it to feel dependable — so the decision is recorded and
answered, and delivery happens behind it.

The trade is that the API response cannot report whether the alert arrived. That
is the right way round: whether a *person decided* is what the response is about,
and whether a *message landed* is a separate fact with its own record, its own
screen, and its own dead-letter queue.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from backend.services.notifications import UnapprovedDispatchError, dispatch_alert
from config.logging import get_logger
from models.notification import AlertRequest

if TYPE_CHECKING:
    from collections.abc import Mapping
    from uuid import UUID

    from config.settings import Settings
    from integrations.notifications import NotificationChannelAdapter
    from models.enums import NotificationChannel

SessionFactory = Callable[[], Session]

_logger = get_logger(__name__)


def deliver_alert(
    session_factory: SessionFactory,
    *,
    payload: dict[str, Any],
    approval_id: UUID,
    settings: Settings,
    channels: Mapping[NotificationChannel, NotificationChannelAdapter],
    actor_id: UUID | None = None,
    console_url: str | None = None,
) -> None:
    """Dispatch one alert the graph prepared, in its own transaction.

    The approval id is supplied by the caller from the decision it just recorded,
    not read out of the graph's payload. Graph state is derived from ingested
    content, and the authority to alert someone must not be readable from
    anything an investigation's *inputs* could influence (invariant #3).
    """
    session = session_factory()
    try:
        alert = AlertRequest.model_validate(
            {**payload, "approval_id": approval_id, "console_url": console_url}
        )
    except ValueError as exc:
        # A malformed alert is dropped rather than dispatched half-formed: a
        # message missing the thing that made it urgent is worse than silence,
        # and the approval and the investigation both remain in the record.
        _logger.error("notification_payload_invalid", error=str(exc), approval_id=str(approval_id))
        session.close()
        return

    try:
        result = dispatch_alert(
            session,
            alert=alert,
            settings=settings,
            channels=channels,
            actor_id=actor_id,
        )
        session.commit()
    except UnapprovedDispatchError as exc:
        session.rollback()
        # Loud, because this is the guard the whole module exists for: something
        # asked to alert on an authority that does not hold up.
        _logger.error(
            "notification_dispatch_unapproved",
            approval_id=str(approval_id),
            investigation_id=str(alert.investigation_id),
            error=str(exc),
        )
        return
    except Exception as exc:
        session.rollback()
        _logger.error(
            "notification_dispatch_failed",
            approval_id=str(approval_id),
            investigation_id=str(alert.investigation_id),
            error=str(exc),
            exc_info=True,
        )
        return
    finally:
        session.close()

    _logger.info(
        "notification_dispatched",
        investigation_id=str(alert.investigation_id),
        delivered=result.delivered,
        dead_lettered=result.dead_lettered,
        suppressed=not result.attempted and not result.no_channel_configured,
    )

"""Data access for outbound notifications.

Delivery records are **append-and-update**: a row is created when a delivery is
first attempted and updated as attempts accumulate, but it is never deleted. What
was sent, to whom, on whose authority, and whether it arrived is exactly the
history an incident review asks for, and it is worthless if it can be tidied up.

The dedupe key is looked up rather than searched for, because idempotency depends
on two callers agreeing about the same delivery — see ``services.notifications``
for how the key is derived.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from backend.db.orm.notification import Notification
from backend.db.repositories.base import Repository
from models.enums import NotificationStatus

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from sqlalchemy.orm import Session


class NotificationRepository(Repository[Notification]):
    """Access to the outbound alert record."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Notification)

    def by_dedupe_key(self, dedupe_key: str) -> Notification | None:
        """The existing delivery record for a key, if one was already created."""
        stmt = select(Notification).where(Notification.dedupe_key == dedupe_key)
        return self._session.execute(stmt).scalars().first()

    def for_approval(self, approval_id: UUID) -> list[Notification]:
        """Every delivery attempted on the authority of one human decision."""
        stmt = (
            select(Notification)
            .where(Notification.approval_id == approval_id)
            .order_by(Notification.created_at)
        )
        return list(self._session.execute(stmt).scalars().all())

    def dead_lettered(self, *, limit: int = 100) -> list[Notification]:
        """Alerts that reached nobody on any channel.

        The queue an operator has to be able to see. A dead letter that is only
        discoverable by grepping logs is one that stays undiscovered.
        """
        stmt = (
            select(Notification)
            .where(Notification.status == NotificationStatus.DEAD_LETTER)
            .order_by(Notification.created_at.desc())
            .limit(limit)
        )
        return list(self._session.execute(stmt).scalars().all())

    def count_by_status(self, status: NotificationStatus) -> int:
        """How many deliveries are in a given state."""
        stmt = select(func.count()).select_from(Notification).where(Notification.status == status)
        return int(self._session.execute(stmt).scalar_one())

    def page(
        self,
        *,
        limit: int,
        offset: int,
        investigation_id: UUID | None = None,
        status: NotificationStatus | None = None,
    ) -> tuple[Sequence[Notification], int]:
        """A page of history plus its total under the same filters."""
        conditions = []
        if investigation_id is not None:
            conditions.append(Notification.investigation_id == investigation_id)
        if status is not None:
            conditions.append(Notification.status == status)

        total = self._session.execute(
            select(func.count()).select_from(Notification).where(*conditions)
        ).scalar_one()
        rows = (
            self._session.execute(
                select(Notification)
                .where(*conditions)
                .order_by(Notification.created_at.desc(), Notification.id.desc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )
        return rows, int(total)

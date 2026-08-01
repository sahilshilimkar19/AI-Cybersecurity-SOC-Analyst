"""Conversation memory — the human-in-the-loop thread (EDS §7).

Durable in PostgreSQL and written by the backend on each human turn or decision;
this tier only **reads** it back so an agent turn can see what was asked, decided,
and by whom. It is part of the audit context, so nothing here mutates it.

Message content is human- and log-derived and therefore untrusted (invariant #3);
it is carried as data and escaped at the point of display, never interpreted here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from models.memory import ConversationTurn

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager

    from sqlalchemy.orm import Session


class ConversationMemory(Protocol):
    """Read access to an investigation's human/system dialogue."""

    def recent_turns(
        self, investigation_id: UUID, *, limit: int = 20
    ) -> list[ConversationTurn]: ...


class InMemoryConversationMemory:
    """In-process conversation memory for tests and local development."""

    def __init__(self) -> None:
        self._turns: dict[UUID, list[ConversationTurn]] = {}

    def add(self, investigation_id: UUID, turn: ConversationTurn) -> None:
        self._turns.setdefault(investigation_id, []).append(turn)

    def recent_turns(self, investigation_id: UUID, *, limit: int = 20) -> list[ConversationTurn]:
        return self._turns.get(investigation_id, [])[-limit:]


class SqlConversationMemory:
    """PostgreSQL-backed conversation memory."""

    def __init__(self, session_scope: Callable[[], AbstractContextManager[Session]]) -> None:
        self._session_scope = session_scope

    def recent_turns(self, investigation_id: UUID, *, limit: int = 20) -> list[ConversationTurn]:
        """Return the most recent dialogue turns, oldest first.

        ``id`` breaks ties on ``created_at``: turns written inside one transaction
        share a timestamp (Postgres ``now()`` is the transaction clock), and
        without a tiebreaker ``LIMIT`` would pick among them arbitrarily.
        """
        from sqlalchemy import select

        from backend.db.orm.conversation import Conversation, Message

        with self._session_scope() as session:
            stmt = (
                select(Message)
                .join(Conversation, Message.conversation_id == Conversation.id)
                .where(Conversation.investigation_id == investigation_id)
                .order_by(Message.created_at.desc(), Message.id.desc())
                .limit(limit)
            )
            rows = list(session.execute(stmt).scalars().all())

        rows.reverse()
        return [
            ConversationTurn(
                author_type=str(row.author_type),
                content=row.content,
                created_at=row.created_at,
            )
            for row in rows
        ]

"""ORM models: conversations, messages, human_decisions."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    str_enum_column,
)
from models.enums import DecisionType, MessageAuthorType


class Conversation(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A human/system dialogue thread attached to an investigation."""

    __tablename__ = "conversations"

    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id"), index=True)


class Message(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single dialogue turn. Append-only."""

    __tablename__ = "messages"
    __table_args__ = (Index("ix_messages_conversation_created", "conversation_id", "created_at"),)

    conversation_id: Mapped[UUID] = mapped_column(ForeignKey("conversations.id"), index=True)
    author_type: Mapped[MessageAuthorType] = mapped_column(
        str_enum_column(MessageAuthorType, "message_author_type")
    )
    author_id: Mapped[UUID | None] = mapped_column(nullable=True)
    content: Mapped[str] = mapped_column(String())


class HumanDecision(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A recorded human decision at an approval gate. Append-only; feeds audit."""

    __tablename__ = "human_decisions"

    conversation_id: Mapped[UUID] = mapped_column(ForeignKey("conversations.id"), index=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    decision: Mapped[DecisionType] = mapped_column(str_enum_column(DecisionType, "decision_type"))
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rationale: Mapped[str | None] = mapped_column(String(), nullable=True)

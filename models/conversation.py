"""Conversation, message, and human-decision domain contracts.

Together these preserve the human-in-the-loop record for an investigation
(governing invariant #1).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from models.base import IdentifiedModel
from models.enums import DecisionType, MessageAuthorType


class Conversation(IdentifiedModel):
    """A human/system dialogue thread attached to an investigation."""

    investigation_id: UUID
    deleted_at: datetime | None = None


class Message(IdentifiedModel):
    """A single dialogue turn. Append-only."""

    conversation_id: UUID
    author_type: MessageAuthorType
    author_id: UUID | None = None
    content: str


class HumanDecision(IdentifiedModel):
    """A recorded human decision at an approval gate. Append-only; feeds audit."""

    conversation_id: UUID
    user_id: UUID
    decision: DecisionType
    target: str | None = None
    rationale: str | None = None

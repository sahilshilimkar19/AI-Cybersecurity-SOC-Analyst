"""Audit log domain contract.

Audit entries are append-only and tamper-evident: each carries a content
``signature`` (a hash over its fields). They are never updated, versioned, or
soft-deleted — they are the history (EDS §6, SAD §14).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from models.base import DomainModel


class AuditLog(DomainModel):
    """An immutable audit record of a consequential action."""

    id: UUID
    created_at: datetime
    actor_id: UUID | None = None
    action: str
    entity_type: str
    entity_id: UUID | None = None
    before_ref: str | None = None
    after_ref: str | None = None
    ip_address: str | None = None
    signature: str

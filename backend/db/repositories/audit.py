"""Append-only repository for the tamper-evident audit trail.

The audit trail is never updated or deleted (governing invariant #1; EDS §6).
Each entry carries a SHA-256 content ``signature`` over its semantic fields,
providing tamper-evidence. Cryptographic signing / hash-chaining is hardened in
the Security sprint.
"""

from __future__ import annotations

import hashlib
import json
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.db.orm.audit import AuditLog


def compute_signature(payload: dict[str, str | None]) -> str:
    """Return a stable SHA-256 hex digest over an audit entry's fields."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogRepository:
    """Writes audit records. Append-only: it exposes no update or delete."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(
        self,
        *,
        action: str,
        entity_type: str,
        entity_id: UUID | None = None,
        actor_id: UUID | None = None,
        before_ref: str | None = None,
        after_ref: str | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """Append a tamper-evident audit entry and return it."""
        entry_id = uuid4()
        signature = compute_signature(
            {
                "id": str(entry_id),
                "action": action,
                "entity_type": entity_type,
                "entity_id": str(entity_id) if entity_id else None,
                "actor_id": str(actor_id) if actor_id else None,
                "before_ref": before_ref,
                "after_ref": after_ref,
                "ip_address": ip_address,
            }
        )
        entry = AuditLog(
            id=entry_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_id=actor_id,
            before_ref=before_ref,
            after_ref=after_ref,
            ip_address=ip_address,
            signature=signature,
        )
        self._session.add(entry)
        self._session.flush()
        return entry

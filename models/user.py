"""User domain contract."""

from __future__ import annotations

from datetime import datetime

from models.base import IdentifiedModel
from models.enums import UserRole, UserStatus


class User(IdentifiedModel):
    """An analyst, manager, admin, or auditor. Deactivated, never hard-deleted."""

    email: str
    name: str
    role: UserRole
    sso_subject: str | None = None
    status: UserStatus = UserStatus.ACTIVE
    deleted_at: datetime | None = None

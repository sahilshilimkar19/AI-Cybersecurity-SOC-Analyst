"""ORM model: users."""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from backend.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    str_enum_column,
)
from models.enums import UserRole, UserStatus


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """An analyst, manager, admin, or auditor."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(str_enum_column(UserRole, "user_role"))
    sso_subject: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    status: Mapped[UserStatus] = mapped_column(
        str_enum_column(UserStatus, "user_status"), default=UserStatus.ACTIVE
    )

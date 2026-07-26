"""SQLAlchemy declarative base, naming conventions, and shared column mixins.

All ORM models inherit from :class:`Base`. A deterministic naming convention
keeps constraint/index names stable across migrations. Mixins provide the common
identity, timestamp, and soft-delete columns (EDS §6).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TypeVar
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import Uuid

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

_E = TypeVar("_E", bound=StrEnum)


def str_enum_column(enum_cls: type[_E], name: str) -> SAEnum:
    """Build an enum column stored as ``VARCHAR`` with a ``CHECK`` constraint.

    ``StrEnum`` members are stored by their string value (e.g. ``"analyst"``) so
    the database representation matches the domain contracts in ``models/``.

    Non-native enums (rather than PostgreSQL ``ENUM`` types) are used so that
    migrations upgrade and downgrade cleanly: dropping a table also drops its
    check constraint, whereas native enum *types* would leak on downgrade.
    """
    return SAEnum(
        enum_cls,
        name=name,
        values_callable=lambda enum: [member.value for member in enum],
        native_enum=False,
        create_constraint=True,
    )


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """Adds a UUID primary key generated on the client."""

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)


class TimestampMixin:
    """Adds ``created_at`` / ``updated_at`` audit timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Adds a nullable ``deleted_at`` for soft deletion (EDS §6)."""

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None, nullable=True
    )

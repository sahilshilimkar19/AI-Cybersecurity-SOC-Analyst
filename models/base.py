"""Base classes for domain contracts.

Domain models are the canonical, transport-agnostic representation of the
system's entities and value objects. They are validated Pydantic models and can
be constructed directly from ORM instances (``from_attributes``).

See docs/ENGINEERING_DESIGN_SPEC.md §3.13.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DomainModel(BaseModel):
    """Base for all domain models and value objects.

    ``extra="forbid"`` makes contracts strict; ``from_attributes=True`` allows
    building a model from an ORM row.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class IdentifiedModel(DomainModel):
    """Base for persisted entities that carry an identity and audit timestamps."""

    id: UUID
    created_at: datetime
    updated_at: datetime

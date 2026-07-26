"""Investigation and Asset domain contracts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from models.base import IdentifiedModel
from models.enums import AssetEnvironment, InvestigationStatus, Severity, TriggerSource


class Asset(IdentifiedModel):
    """A host, system, or software involved in an investigation."""

    hostname: str | None = None
    ip_address: str | None = None
    operating_system: str | None = None
    software_inventory: dict[str, str] = Field(default_factory=dict)
    owner: str | None = None
    environment: AssetEnvironment = AssetEnvironment.UNKNOWN
    deleted_at: datetime | None = None


class Investigation(IdentifiedModel):
    """The central case record.

    ``config_snapshot`` pins the configuration in effect at creation so the
    investigation remains reproducible even if global config later changes
    (EDS §4).
    """

    trigger_source: TriggerSource
    status: InvestigationStatus = InvestigationStatus.OPEN
    severity: Severity | None = None
    owner_id: UUID | None = None
    title: str | None = None
    summary: str | None = None
    config_snapshot: dict[str, object] = Field(default_factory=dict)
    closed_at: datetime | None = None
    deleted_at: datetime | None = None

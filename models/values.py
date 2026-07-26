"""Embedded value objects used within entity contracts.

These are not persisted as their own tables; they are stored as structured JSON
within their owning entity (for example an assessment's IoCs).
"""

from __future__ import annotations

from pydantic import Field

from models.base import DomainModel
from models.enums import Severity


class Cvss(DomainModel):
    """CVSS severity for a CVE."""

    score: float = Field(ge=0.0, le=10.0)
    vector: str | None = None
    severity: Severity


class Ioc(DomainModel):
    """An indicator of compromise with optional reputation context."""

    type: str
    value: str
    reputation: str | None = None
    source: str | None = None


class AttackTechnique(DomainModel):
    """A MITRE ATT&CK technique mapped to observed activity."""

    technique_id: str
    name: str | None = None
    rationale: str | None = None


class Citation(DomainModel):
    """A source reference bound to a grounded claim (invariant #4)."""

    source_id: str
    source: str
    url: str | None = None

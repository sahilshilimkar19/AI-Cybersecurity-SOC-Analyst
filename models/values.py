"""Embedded value objects used within entity contracts.

These are not persisted as their own tables; they are stored as structured JSON
within their owning entity (for example an assessment's IoCs).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from models.base import DomainModel
from models.enums import Severity, SourceTrustTier


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
    """A source reference bound to a grounded claim (invariant #4).

    The RAG citation binder produces these, and the Reporter compiles them into a
    reference list, so retrieval and reporting share one citation contract. The
    optional fields are filled in when the citation comes from the knowledge index:
    ``chunk_id`` locates the exact passage, and the trust tier and publication date
    let a reader judge the strength and currency of the support.
    """

    source_id: str
    source: str
    url: str | None = None
    chunk_id: str | None = None
    title: str | None = None
    trust_tier: SourceTrustTier | None = None
    published_at: datetime | None = None

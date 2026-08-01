"""Knowledge sources: the allow-list, their trust tiers, and refresh cadence.

Only allow-listed sources may ground an answer. This is a **security control, not
a curation preference**: the corpus agents reason from is the one thing in this
system that must stay trustworthy, so unknown provenance is excluded outright
rather than merely ranked low (EDS §8, invariant #3).

Fetching is a port. Documents arrive from a filesystem (internal runbooks,
detection rules, policies — a real production source) or from an in-process
collection in tests. The HTTP adapters for NVD, MITRE, and vendor advisories live
in the integrations layer and are built by the sprints that own them; they satisfy
this same protocol, so nothing here changes when they land.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from config.logging import get_logger
from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import ChunkMetadata, SourceDocument
from rag.errors import UntrustedSourceError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_logger = get_logger(__name__)


@dataclass(frozen=True)
class SourceDefinition:
    """An allow-listed knowledge source.

    ``refresh_interval_hours`` is the scheduled cadence; high-severity advisories
    are additionally refreshed on demand rather than waiting for the next tick.
    """

    source_id: str
    name: str
    kind: KnowledgeSourceKind
    trust_tier: SourceTrustTier
    refresh_interval_hours: int
    description: str = ""


# The allow-list. Trust tiers follow authority: NVD and MITRE are the canonical
# public records; vendor advisories are authoritative for their own products;
# internal runbooks are trusted but organization-specific rather than universal.
DEFAULT_SOURCES: tuple[SourceDefinition, ...] = (
    SourceDefinition(
        source_id="nvd",
        name="NVD CVE Feed",
        kind=KnowledgeSourceKind.NVD,
        trust_tier=SourceTrustTier.AUTHORITATIVE,
        refresh_interval_hours=6,
        description="National Vulnerability Database CVE records and CVSS scores.",
    ),
    SourceDefinition(
        source_id="mitre_attack",
        name="MITRE ATT&CK",
        kind=KnowledgeSourceKind.MITRE_ATTACK,
        trust_tier=SourceTrustTier.AUTHORITATIVE,
        refresh_interval_hours=168,
        description="Adversary tactics and techniques taxonomy.",
    ),
    SourceDefinition(
        source_id="vendor_advisories",
        name="Vendor & GitHub Security Advisories",
        kind=KnowledgeSourceKind.ADVISORY,
        trust_tier=SourceTrustTier.VENDOR,
        refresh_interval_hours=12,
        description="Package- and product-level security advisories.",
    ),
    SourceDefinition(
        source_id="internal_runbooks",
        name="Internal Runbooks & Detection Rules",
        kind=KnowledgeSourceKind.INTERNAL_RUNBOOK,
        trust_tier=SourceTrustTier.INTERNAL,
        refresh_interval_hours=24,
        description="Curated internal response runbooks, detection rules, and policies.",
    ),
)


class SourceRegistry:
    """The allow-list of sources permitted to ground answers."""

    def __init__(self, definitions: Iterable[SourceDefinition] = DEFAULT_SOURCES) -> None:
        self._definitions = {definition.source_id: definition for definition in definitions}

    def __contains__(self, source_id: object) -> bool:
        return source_id in self._definitions

    def all(self) -> list[SourceDefinition]:
        """Every allow-listed source, in registration order."""
        return list(self._definitions.values())

    def get(self, source_id: str) -> SourceDefinition:
        """Return a source definition, refusing anything not allow-listed."""
        definition = self._definitions.get(source_id)
        if definition is None:
            raise UntrustedSourceError(f"source is not allow-listed: {source_id!r}")
        return definition

    def require_trusted(self, document: SourceDocument) -> SourceDefinition:
        """Validate that a document came from an allow-listed source."""
        return self.get(document.metadata.source_id)


class DocumentFetcher(Protocol):
    """Fetches the current documents for one source."""

    def fetch(self, definition: SourceDefinition) -> Sequence[SourceDocument]: ...


@dataclass
class InMemoryFetcher:
    """Serves documents from an in-process mapping (tests and fixtures)."""

    documents: dict[str, list[SourceDocument]] = field(default_factory=dict)

    def add(self, source_id: str, document: SourceDocument) -> None:
        self.documents.setdefault(source_id, []).append(document)

    def fetch(self, definition: SourceDefinition) -> Sequence[SourceDocument]:
        return list(self.documents.get(definition.source_id, []))


class FilesystemFetcher:
    """Reads documents from a directory of JSON files, one per document.

    This is how curated internal knowledge (runbooks, detection rules, policies)
    enters the corpus, and how offline snapshots of public feeds are ingested
    without a network dependency.

    Each file holds ``{"document_id", "title", "content", ...optional metadata}``.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def fetch(self, definition: SourceDefinition) -> Sequence[SourceDocument]:
        directory = self._root / definition.source_id
        if not directory.is_dir():
            _logger.info(
                "source_directory_missing", source_id=definition.source_id, path=str(directory)
            )
            return []

        documents: list[SourceDocument] = []
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                # One malformed file must not abort the source: quarantine and continue.
                _logger.warning("source_document_unreadable", path=str(path), exc_info=True)
                continue
            document = self._build(definition, payload, fallback_id=path.stem)
            if document is not None:
                documents.append(document)
        return documents

    @staticmethod
    def _build(
        definition: SourceDefinition, payload: dict[str, Any], *, fallback_id: str
    ) -> SourceDocument | None:
        content = str(payload.get("content", "")).strip()
        if not content:
            return None
        raw_products = payload.get("products") or []
        metadata = ChunkMetadata(
            source_kind=definition.kind,
            source_id=definition.source_id,
            source_name=definition.name,
            trust_tier=definition.trust_tier,
            source_version=_optional_str(payload.get("source_version")),
            # Dates are left as-is; Pydantic validates ISO-8601 consistently.
            published_at=payload.get("published_at"),
            updated_at=payload.get("updated_at"),
            cve_id=_optional_str(payload.get("cve_id")),
            cwe_id=_optional_str(payload.get("cwe_id")),
            technique_id=_optional_str(payload.get("technique_id")),
            products=[str(item) for item in raw_products],
            url=_optional_str(payload.get("url")),
        )
        return SourceDocument(
            document_id=str(payload.get("document_id") or fallback_id),
            title=str(payload.get("title") or fallback_id),
            content=content,
            metadata=metadata,
        )


def _optional_str(value: object) -> str | None:
    return str(value) if value is not None else None

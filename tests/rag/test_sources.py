"""Tests for the source allow-list and document fetchers."""

import json
from pathlib import Path

import pytest

from models.enums import KnowledgeSourceKind, SourceTrustTier
from rag.errors import UntrustedSourceError
from rag.sources import (
    DEFAULT_SOURCES,
    FilesystemFetcher,
    InMemoryFetcher,
    SourceRegistry,
)
from tests.rag.conftest import CORPUS


def test_default_sources_cover_the_specified_knowledge_sources() -> None:
    kinds = {definition.kind for definition in DEFAULT_SOURCES}
    assert kinds == {
        KnowledgeSourceKind.NVD,
        KnowledgeSourceKind.MITRE_ATTACK,
        KnowledgeSourceKind.ADVISORY,
        KnowledgeSourceKind.INTERNAL_RUNBOOK,
    }


def test_every_source_has_a_trust_tier_and_refresh_cadence() -> None:
    for definition in DEFAULT_SOURCES:
        assert isinstance(definition.trust_tier, SourceTrustTier)
        assert definition.refresh_interval_hours > 0


def test_registry_returns_allow_listed_sources() -> None:
    registry = SourceRegistry()
    assert registry.get("nvd").kind is KnowledgeSourceKind.NVD
    assert "nvd" in registry


def test_registry_refuses_sources_not_on_the_allow_list() -> None:
    registry = SourceRegistry()
    with pytest.raises(UntrustedSourceError):
        registry.get("random-blog")
    assert "random-blog" not in registry


def test_require_trusted_validates_a_documents_source() -> None:
    registry = SourceRegistry()
    document = CORPUS[0]
    assert registry.require_trusted(document).source_id == "nvd"


def test_in_memory_fetcher_returns_documents_for_its_source() -> None:
    fetcher = InMemoryFetcher()
    fetcher.add("nvd", CORPUS[0])
    registry = SourceRegistry()

    assert len(fetcher.fetch(registry.get("nvd"))) == 1
    assert fetcher.fetch(registry.get("mitre_attack")) == []


def test_filesystem_fetcher_reads_json_documents(tmp_path: Path) -> None:
    directory = tmp_path / "internal_runbooks"
    directory.mkdir()
    (directory / "playbook.json").write_text(
        json.dumps(
            {
                "document_id": "rb-1",
                "title": "Phishing response",
                "content": "Quarantine the message and reset credentials.",
                "products": ["exchange"],
                "published_at": "2026-02-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    documents = FilesystemFetcher(tmp_path).fetch(SourceRegistry().get("internal_runbooks"))

    assert len(documents) == 1
    assert documents[0].document_id == "rb-1"
    assert documents[0].metadata.products == ["exchange"]
    assert documents[0].metadata.trust_tier is SourceTrustTier.INTERNAL
    assert documents[0].metadata.published_at is not None


def test_filesystem_fetcher_handles_a_missing_directory(tmp_path: Path) -> None:
    assert FilesystemFetcher(tmp_path).fetch(SourceRegistry().get("nvd")) == []


def test_filesystem_fetcher_quarantines_unreadable_files(tmp_path: Path) -> None:
    directory = tmp_path / "internal_runbooks"
    directory.mkdir()
    (directory / "broken.json").write_text("{not json", encoding="utf-8")
    (directory / "good.json").write_text(
        json.dumps({"document_id": "ok", "title": "Fine", "content": "usable content"}),
        encoding="utf-8",
    )

    documents = FilesystemFetcher(tmp_path).fetch(SourceRegistry().get("internal_runbooks"))

    # One bad file must not cost us the rest of the source.
    assert [document.document_id for document in documents] == ["ok"]


def test_filesystem_fetcher_skips_documents_without_content(tmp_path: Path) -> None:
    directory = tmp_path / "internal_runbooks"
    directory.mkdir()
    (directory / "empty.json").write_text(json.dumps({"content": "   "}), encoding="utf-8")

    assert FilesystemFetcher(tmp_path).fetch(SourceRegistry().get("internal_runbooks")) == []

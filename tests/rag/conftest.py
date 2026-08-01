"""Fixtures and the labeled corpus used by the RAG suite.

The corpus is small but shaped like the real one: authoritative CVE records, an
ATT&CK technique, a vendor advisory, and an internal runbook, with the publication
dates and trust tiers that drive ranking.
"""

from datetime import UTC, datetime

import pytest

from config.settings import Settings
from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import ChunkMetadata, SourceDocument
from rag.service import RagService, build_rag_service
from rag.sources import InMemoryFetcher

NOW = datetime(2026, 8, 1, tzinfo=UTC)


def make_document(
    *,
    document_id: str,
    title: str,
    content: str,
    source_id: str,
    kind: KnowledgeSourceKind,
    trust: SourceTrustTier,
    published: datetime | None = None,
    cve_id: str | None = None,
    technique_id: str | None = None,
    products: list[str] | None = None,
) -> SourceDocument:
    return SourceDocument(
        document_id=document_id,
        title=title,
        content=content,
        metadata=ChunkMetadata(
            source_kind=kind,
            source_id=source_id,
            source_name=source_id.replace("_", " ").title(),
            trust_tier=trust,
            published_at=published,
            cve_id=cve_id,
            technique_id=technique_id,
            products=products or [],
            url=f"https://example.invalid/{document_id}",
        ),
    )


CORPUS: list[SourceDocument] = [
    make_document(
        document_id="CVE-2021-44228",
        title="CVE-2021-44228 Log4Shell",
        content=(
            "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP "
            "endpoints. A remote attacker who can control log messages can execute arbitrary "
            "code. Affected versions are log4j-core 2.0-beta9 through 2.14.1."
        ),
        source_id="nvd",
        kind=KnowledgeSourceKind.NVD,
        trust=SourceTrustTier.AUTHORITATIVE,
        published=datetime(2021, 12, 10, tzinfo=UTC),
        cve_id="CVE-2021-44228",
        products=["log4j-core", "apache-log4j2"],
    ),
    make_document(
        document_id="CVE-2024-3094",
        title="CVE-2024-3094 XZ Utils backdoor",
        content=(
            "Malicious code was discovered in the upstream tarballs of xz utils. The backdoor "
            "modifies liblzma and can allow remote unauthenticated access via sshd."
        ),
        source_id="nvd",
        kind=KnowledgeSourceKind.NVD,
        trust=SourceTrustTier.AUTHORITATIVE,
        published=datetime(2024, 3, 29, tzinfo=UTC),
        cve_id="CVE-2024-3094",
        products=["xz-utils", "liblzma"],
    ),
    make_document(
        document_id="T1059",
        title="T1059 Command and Scripting Interpreter",
        content=(
            "Adversaries abuse command and script interpreters to execute commands or "
            "binaries. Detection focuses on unusual parent process relationships and "
            "suspicious command line arguments."
        ),
        source_id="mitre_attack",
        kind=KnowledgeSourceKind.MITRE_ATTACK,
        trust=SourceTrustTier.AUTHORITATIVE,
        published=datetime(2020, 1, 1, tzinfo=UTC),
        technique_id="T1059",
    ),
    make_document(
        document_id="GHSA-log4j",
        title="Vendor advisory for log4j remediation",
        content=(
            "Upgrade log4j-core to 2.17.1 or later. If upgrading is not possible remove the "
            "JndiLookup class from the classpath as a mitigation."
        ),
        source_id="vendor_advisories",
        kind=KnowledgeSourceKind.ADVISORY,
        trust=SourceTrustTier.VENDOR,
        published=datetime(2021, 12, 18, tzinfo=UTC),
        cve_id="CVE-2021-44228",
        products=["log4j-core"],
    ),
    make_document(
        document_id="runbook-ransomware",
        title="Ransomware containment runbook",
        content=(
            "Isolate affected hosts from the network. Preserve volatile evidence before "
            "shutdown. Notify the incident commander and begin restoring from known good "
            "backups only after the intrusion vector is understood."
        ),
        source_id="internal_runbooks",
        kind=KnowledgeSourceKind.INTERNAL_RUNBOOK,
        trust=SourceTrustTier.INTERNAL,
        published=datetime(2026, 1, 15, tzinfo=UTC),
    ),
]


@pytest.fixture
def settings() -> Settings:
    """Settings with a small top-k so ranking behaviour is observable."""
    return Settings(rag_retrieval_top_k=3, rag_cache_ttl_seconds=300)


@pytest.fixture
def fetcher() -> InMemoryFetcher:
    source = InMemoryFetcher()
    for document in CORPUS:
        source.add(document.metadata.source_id, document)
    return source


@pytest.fixture
def rag(settings: Settings, fetcher: InMemoryFetcher) -> RagService:
    """A RAG service with the labeled corpus fully ingested."""
    service = build_rag_service(settings, fetcher=fetcher)
    service.refresh_all()
    return service

"""Tests for metadata filter predicates and context-driven query expansion."""

from datetime import UTC, datetime

from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import ChunkMetadata, KnowledgeChunkRecord, RetrievalFilters
from rag.index import keyword_overlap_score, matches_filters, trust_rank
from rag.retriever import expand_query


def _record(
    *,
    kind: KnowledgeSourceKind = KnowledgeSourceKind.NVD,
    trust: SourceTrustTier = SourceTrustTier.AUTHORITATIVE,
    cve_id: str | None = None,
    technique_id: str | None = None,
    products: list[str] | None = None,
    published: datetime | None = None,
    content: str = "body text",
    title: str | None = None,
) -> KnowledgeChunkRecord:
    return KnowledgeChunkRecord(
        chunk_id="c1",
        document_id="d1",
        title=title,
        content=content,
        metadata=ChunkMetadata(
            source_kind=kind,
            source_id="nvd",
            source_name="NVD",
            trust_tier=trust,
            cve_id=cve_id,
            technique_id=technique_id,
            products=products or [],
            published_at=published,
        ),
    )


def test_empty_filters_match_everything() -> None:
    filters = RetrievalFilters()
    assert filters.is_empty()
    assert matches_filters(_record(), filters)


def test_filters_with_any_constraint_are_not_empty() -> None:
    assert not RetrievalFilters(cve_ids=["CVE-1"]).is_empty()
    assert not RetrievalFilters(minimum_trust=SourceTrustTier.VENDOR).is_empty()


def test_source_kind_filter() -> None:
    filters = RetrievalFilters(source_kinds=[KnowledgeSourceKind.ADVISORY])
    assert not matches_filters(_record(kind=KnowledgeSourceKind.NVD), filters)
    assert matches_filters(_record(kind=KnowledgeSourceKind.ADVISORY), filters)


def test_cve_filter_excludes_records_without_that_cve() -> None:
    filters = RetrievalFilters(cve_ids=["CVE-2021-44228"])
    assert matches_filters(_record(cve_id="CVE-2021-44228"), filters)
    assert not matches_filters(_record(cve_id="CVE-2024-3094"), filters)
    assert not matches_filters(_record(cve_id=None), filters)


def test_technique_filter_excludes_records_without_that_technique() -> None:
    filters = RetrievalFilters(technique_ids=["T1059"])
    assert matches_filters(_record(technique_id="T1059"), filters)
    assert not matches_filters(_record(technique_id=None), filters)


def test_product_filter_matches_on_any_overlap() -> None:
    filters = RetrievalFilters(products=["log4j-core", "nginx"])
    assert matches_filters(_record(products=["log4j-core"]), filters)
    assert not matches_filters(_record(products=["openssl"]), filters)
    assert not matches_filters(_record(products=[]), filters)


def test_published_after_filter_excludes_older_and_undated_records() -> None:
    cutoff = datetime(2024, 1, 1, tzinfo=UTC)
    filters = RetrievalFilters(published_after=cutoff)

    assert matches_filters(_record(published=datetime(2025, 1, 1, tzinfo=UTC)), filters)
    assert not matches_filters(_record(published=datetime(2023, 1, 1, tzinfo=UTC)), filters)
    # Undated records cannot prove they are recent enough.
    assert not matches_filters(_record(published=None), filters)


def test_minimum_trust_filter_admits_equal_or_more_authoritative_sources() -> None:
    filters = RetrievalFilters(minimum_trust=SourceTrustTier.VENDOR)

    assert matches_filters(_record(trust=SourceTrustTier.AUTHORITATIVE), filters)
    assert matches_filters(_record(trust=SourceTrustTier.VENDOR), filters)
    assert not matches_filters(_record(trust=SourceTrustTier.COMMUNITY), filters)


def test_trust_rank_orders_by_authority() -> None:
    assert trust_rank(SourceTrustTier.AUTHORITATIVE) < trust_rank(SourceTrustTier.VENDOR)
    assert trust_rank(SourceTrustTier.VENDOR) < trust_rank(SourceTrustTier.COMMUNITY)


def test_keyword_score_is_zero_for_an_empty_query() -> None:
    assert keyword_overlap_score("", _record()) == 0.0


def test_the_record_owning_an_identifier_outranks_one_merely_mentioning_it() -> None:
    """Why exact CVE queries land on the canonical record rather than on prose."""
    query = "CVE-2021-44228"
    canonical = _record(
        cve_id="CVE-2021-44228",
        title="CVE-2021-44228 Log4Shell",
        content="Apache Log4j2 JNDI flaw in CVE-2021-44228.",
    )
    mention = _record(cve_id=None, content="See CVE-2021-44228 for background details.")

    assert keyword_overlap_score(query, canonical) > keyword_overlap_score(query, mention)


def test_identifier_boost_applies_on_top_of_text_overlap() -> None:
    without_id = _record(cve_id=None, content="CVE-2021-44228 details")
    with_id = _record(cve_id="CVE-2021-44228", content="CVE-2021-44228 details")

    assert keyword_overlap_score("CVE-2021-44228", with_id) > keyword_overlap_score(
        "CVE-2021-44228", without_id
    )


def test_keyword_score_considers_the_title() -> None:
    with_title = _record(title="Log4Shell advisory", content="body")
    assert keyword_overlap_score("log4shell", with_title) > 0


def test_keyword_score_uses_coverage_not_raw_frequency() -> None:
    short = _record(content="alpha beta")
    padded = _record(content="alpha beta " + "filler " * 100)
    # Padding a chunk must not make it a better match.
    assert keyword_overlap_score("alpha beta", short) == keyword_overlap_score("alpha beta", padded)


def test_expand_query_appends_investigation_context() -> None:
    expanded = expand_query(
        "suspicious process",
        assets=["web-01"],
        iocs=["1.2.3.4"],
        techniques=["T1059"],
        cves=["CVE-2021-44228"],
    )
    assert expanded.startswith("suspicious process")
    for term in ("web-01", "1.2.3.4", "T1059", "CVE-2021-44228"):
        assert term in expanded


def test_expand_query_without_context_is_the_original_query() -> None:
    assert expand_query("  just a query  ") == "just a query"

"""Retrieval evaluation against a labeled set (EDS §18 RAG definition of done).

This is the gate that turns "retrieval seems fine" into a measured property. Each
case names a query and the document that *should* be retrieved for it; the suite
asserts precision@k and recall@k stay at or above an explicit baseline, so a
regression in chunking, embedding, fusion, or ranking fails the build rather than
quietly degrading every downstream agent.

The baselines are deliberately strict for this corpus. Raising them is fine;
lowering one is a decision that should be argued for in review.
"""

from dataclasses import dataclass

import pytest

from models.knowledge import RetrievalFilters
from rag.service import RagService

# Precision is the share of returned chunks that are relevant; recall is whether
# the expected document was found at all. Recall matters most here: missing the
# authoritative record for a CVE is far worse than returning one extra chunk.
#
# The pipeline currently scores 1.00 on both for this corpus. The baselines sit
# just below that so a genuine regression fails while trivial score jitter does
# not; lowering one is a decision to argue for in review, not a quick fix.
MIN_RECALL_AT_K = 1.0
MIN_PRECISION_AT_1 = 0.875


@dataclass(frozen=True)
class EvalCase:
    query: str
    expected_document_id: str
    description: str


LABELED_SET: tuple[EvalCase, ...] = (
    EvalCase("CVE-2021-44228", "CVE-2021-44228", "exact CVE identifier"),
    EvalCase("Log4Shell JNDI LDAP remote code execution", "CVE-2021-44228", "concept phrasing"),
    EvalCase("xz utils backdoor liblzma sshd", "CVE-2024-3094", "supply chain backdoor"),
    EvalCase("CVE-2024-3094", "CVE-2024-3094", "exact CVE identifier"),
    EvalCase("T1059", "T1059", "exact technique identifier"),
    EvalCase(
        "adversaries abuse command and scripting interpreters", "T1059", "technique description"
    ),
    EvalCase(
        "how do we contain ransomware and restore backups",
        "runbook-ransomware",
        "internal runbook",
    ),
    EvalCase("remove JndiLookup class mitigation upgrade", "GHSA-log4j", "vendor remediation"),
)


def _documents(result: object) -> list[str]:
    return [item.chunk.document_id for item in result.chunks]  # type: ignore[attr-defined]


@pytest.mark.parametrize("case", LABELED_SET, ids=lambda case: case.description)
def test_expected_document_is_retrieved(rag: RagService, case: EvalCase) -> None:
    result = rag.retrieve(case.query)
    assert case.expected_document_id in _documents(result), (
        f"{case.query!r} did not retrieve {case.expected_document_id!r}"
    )


def test_recall_at_k_meets_the_baseline(rag: RagService) -> None:
    hits = sum(
        1
        for case in LABELED_SET
        if case.expected_document_id in _documents(rag.retrieve(case.query))
    )
    recall = hits / len(LABELED_SET)
    assert recall >= MIN_RECALL_AT_K, f"recall@k {recall:.2f} below baseline {MIN_RECALL_AT_K}"


def test_precision_at_1_meets_the_baseline(rag: RagService) -> None:
    top_hits = sum(
        1
        for case in LABELED_SET
        if _documents(rag.retrieve(case.query))[:1] == [case.expected_document_id]
    )
    precision = top_hits / len(LABELED_SET)
    assert precision >= MIN_PRECISION_AT_1, (
        f"precision@1 {precision:.2f} below baseline {MIN_PRECISION_AT_1}"
    )


def test_exact_identifier_queries_rank_their_record_first(rag: RagService) -> None:
    """The keyword path must win for exact identifiers; this is why retrieval is hybrid."""
    for query, expected in (
        ("CVE-2021-44228", "CVE-2021-44228"),
        ("CVE-2024-3094", "CVE-2024-3094"),
        ("T1059", "T1059"),
    ):
        assert _documents(rag.retrieve(query))[0] == expected


def test_conceptual_queries_recover_records_that_share_no_identifier(
    rag: RagService,
) -> None:
    """The dense path must contribute; a purely lexical system would miss these."""
    result = rag.retrieve("interpreter abuse detection using parent process relationships")
    assert "T1059" in _documents(result)


def test_retrieval_is_deterministic(rag: RagService) -> None:
    first = _documents(rag.retrieve("log4j remote code execution"))
    second = _documents(rag.retrieve("log4j remote code execution"))
    assert first == second


def test_unrelated_query_returns_no_grounding(rag: RagService) -> None:
    result = rag.retrieve("zzzz qqqq unrelated gibberish token")
    assert result.is_empty


def test_filters_narrow_retrieval_to_the_requested_slice(rag: RagService) -> None:
    from models.enums import KnowledgeSourceKind

    result = rag.retrieve(
        "log4j",
        filters=RetrievalFilters(source_kinds=[KnowledgeSourceKind.ADVISORY]),
    )
    assert result.chunks
    assert all(
        item.chunk.metadata.source_kind is KnowledgeSourceKind.ADVISORY for item in result.chunks
    )


def test_cve_filter_selects_only_that_cve(rag: RagService) -> None:
    result = rag.retrieve(
        "remote code execution", filters=RetrievalFilters(cve_ids=["CVE-2024-3094"])
    )
    assert result.chunks
    assert all(item.chunk.metadata.cve_id == "CVE-2024-3094" for item in result.chunks)


def test_minimum_trust_filter_excludes_lower_tiers(rag: RagService) -> None:
    from models.enums import SourceTrustTier

    result = rag.retrieve(
        "log4j remediation upgrade",
        filters=RetrievalFilters(minimum_trust=SourceTrustTier.AUTHORITATIVE),
    )
    assert all(
        item.chunk.metadata.trust_tier is SourceTrustTier.AUTHORITATIVE for item in result.chunks
    )

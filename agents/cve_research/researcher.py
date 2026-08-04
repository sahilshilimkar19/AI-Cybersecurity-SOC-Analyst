"""The CVE Research agent (EDS §4.4, SAD §2.3).

Takes the Threat Detector's assessment and the estate's software inventory, and
answers a narrower question than it first appears: *which publicly documented
vulnerabilities are relevant here, and how far can we actually say they apply?*

Three separations do the work, and each exists because collapsing it produces
confident nonsense:

* **Applicability is separate from exploitation.** That a host is vulnerable is
  not evidence it was attacked, and activity resembling an exploit is not
  evidence the host was vulnerable. They are assessed independently and reported
  independently.
* **Confirmed is separate from candidate.** A CVE is confirmed only when a named
  host runs a named product at a version inside a published vulnerable range —
  the contract itself refuses anything weaker. Everything else is a candidate
  carrying *which* piece of evidence was missing, which turns uncertainty into a
  work list rather than a shrug.
* **Live is separate from cached.** When the feed is unreachable the agent
  researches from the indexed corpus and marks the dossier stale. Corpus records
  are structurally weaker — the text carries an identifier and a score but not
  machine-readable version ranges — so they land as candidates, which is the
  truth about what a cached answer can support (EDS §4.4 fallback).

Everything the agent could not do is an output: an unavailable feed, an
unreachable corpus, an inventory it was never given, products it had to skip for
budget. A dossier that cannot say what it did not check is not research.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from agents.shared.contracts import AgentDegradation, AgentOutcome
from config.logging import get_logger
from integrations.nvd import UnavailableCveSource
from models.enums import CveApplicability, SourceTrustTier
from models.values import Citation
from models.vulnerability import (
    ApplicabilityReason,
    CveAssessment,
    CveDataSource,
    CveRecord,
    CveResearchResult,
    ExploitMapping,
)
from prompts.assembly import CVE_RESEARCH_PROMPT
from tools.cvss import interpret
from tools.cwe import known_weakness, normalize_cwe_id
from tools.versions import assess_applicability, products_match

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from integrations.nvd import CveSource
    from memory.knowledge import KnowledgeMemory
    from models.memory import KnowledgeChunk
    from models.vulnerability import ApplicabilityEvidence, AssetContext, CveResearchRequest

_logger = get_logger(__name__)

AGENT_NAME = "cve_research"

# Tools this agent is allow-listed to use (EDS §3.7 least privilege).
ALLOWED_TOOLS = (
    "fetch_cve",
    "search_cve",
    "interpret_cvss",
    "assess_applicability",
    "explain_weakness",
    "retrieve_knowledge",
)

NVD_SOURCE_ID = "nvd"
NVD_SOURCE_NAME = "NVD"
_NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail"

# CVE and CVSS identifiers as they appear in free text, used to read structure
# back out of corpus passages.
_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CVSS_VECTOR = re.compile(r"CVSS:3\.[01]/[A-Z:/]+")
_CWE_IN_TEXT = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

# Chunks retrieved per corpus query.
_CORPUS_LIMIT = 5

# Confidence multipliers. A dossier assembled from cached data is usable; one
# presented as current when it is not, is worse than useless.
_STALE_CONFIDENCE = 0.7
_NO_INVENTORY_CONFIDENCE = 0.5


class CveResearcher:
    """Researches the vulnerabilities relevant to an investigation."""

    def __init__(
        self,
        *,
        cve_source: CveSource | None = None,
        knowledge: KnowledgeMemory | None = None,
        max_products: int = 12,
        results_per_product: int = 10,
    ) -> None:
        self._source = cve_source or UnavailableCveSource()
        self._knowledge = knowledge
        self._max_products = max_products
        self._results_per_product = results_per_product

    def research(self, request: CveResearchRequest) -> AgentOutcome[CveResearchResult]:
        """Assemble a cited vulnerability dossier, reporting what it could not check."""
        degradations: list[AgentDegradation] = []
        context = _ThreatContext.from_payload(request.threat_assessment)

        products, skipped = self._products_to_search(request.assets)
        if skipped:
            degradations.append(
                AgentDegradation(
                    reason="search_budget",
                    detail=f"{skipped} inventory product(s) exceeded the research budget",
                )
            )
        if not request.assets:
            degradations.append(
                AgentDegradation(
                    reason="no_asset_inventory",
                    detail=(
                        "no asset inventory was supplied, so no CVE can be confirmed "
                        "applicable — every finding stays a candidate"
                    ),
                )
            )

        records, notes, degraded_lookups = self._collect(request.referenced_cve_ids, products)
        degradations.extend(notes)

        assessments = [self._assess(record, request.assets, context) for record in records.values()]
        confirmed = [item for item in assessments if item.is_confirmed]
        candidates = [
            item for item in assessments if item.applicability is CveApplicability.CANDIDATE
        ]
        ruled_out = [
            item for item in assessments if item.applicability is CveApplicability.NOT_APPLICABLE
        ]

        # Stale means "this dossier does not rest on current live data" — which
        # includes the case where the feed was unreachable and recovered nothing
        # at all. Reporting an empty dossier as current would let "we could not
        # look" read as "we looked and found nothing".
        stale = degraded_lookups > 0 or any(record.stale for record in records.values())
        confidence = self._confidence(
            assessments=assessments, has_inventory=bool(request.assets), stale=stale
        )

        result = CveResearchResult(
            investigation_id=request.investigation_id,
            cves=sorted(confirmed, key=_by_severity),
            candidates=sorted(candidates, key=_by_severity),
            ruled_out=sorted(ruled_out, key=_by_severity),
            source_freshness=_oldest_modification(list(records.values())),
            stale=stale,
            searched_products=products,
            confidence=confidence,
        )

        _logger.info(
            "cve_research_complete",
            investigation_id=request.investigation_id,
            records=len(records),
            confirmed=len(result.cves),
            candidates=len(result.candidates),
            ruled_out=len(result.ruled_out),
            products_searched=len(products),
            stale=stale,
            confidence=confidence,
        )

        return AgentOutcome(
            agent=AGENT_NAME,
            output=result,
            confidence=confidence,
            prompt_version=CVE_RESEARCH_PROMPT.version,
            tool_calls=[
                {"tool": "fetch_cve", "count": len(request.referenced_cve_ids)},
                {"tool": "search_cve", "count": len(products)},
                {"tool": "assess_applicability", "count": len(assessments)},
                {
                    "tool": "interpret_cvss",
                    "count": sum(1 for item in records.values() if item.cvss is not None),
                },
            ],
            degradations=degradations,
        )

    # --- Collection -------------------------------------------------------

    def _products_to_search(self, assets: Sequence[AssetContext]) -> tuple[list[str], int]:
        """The distinct inventory products to research, bounded by budget."""
        seen: list[str] = []
        for asset in assets:
            for installed in asset.software:
                if installed.product and installed.product not in seen:
                    seen.append(installed.product)
        return seen[: self._max_products], max(0, len(seen) - self._max_products)

    def _collect(
        self, referenced_cve_ids: Sequence[str], products: Sequence[str]
    ) -> tuple[dict[str, CveRecord], list[AgentDegradation], int]:
        """Gather records from the live feed, falling back to the corpus per query.

        Fallback is per-query rather than all-or-nothing: a feed that answers some
        lookups and fails others should contribute what it answered, and the
        dossier is marked stale only for the parts that actually came from cache.

        The shortfall is reported once with the queries it covered, not once per
        query. Ten identical notes are one fact stated ten times, and burying the
        signal is how degradation stops being noticed.

        Returns the records, the notes, and how many lookups had to fall back —
        the last of which marks the dossier stale even when the fallback
        recovered nothing.
        """
        records: dict[str, CveRecord] = {}
        fell_back: list[str] = []
        reasons: set[str] = set()

        for cve_id in referenced_cve_ids:
            self._lookup(cve_id, by_id=True, records=records, fell_back=fell_back, reasons=reasons)
        for product in products:
            self._lookup(
                product, by_id=False, records=records, fell_back=fell_back, reasons=reasons
            )

        if not fell_back:
            return records, [], 0

        recovered = sum(1 for record in records.values() if record.stale)
        note = AgentDegradation(
            reason="live_feed_unavailable",
            detail=(
                f"the live CVE feed was unavailable ({', '.join(sorted(reasons))}) for "
                f"{len(fell_back)} of {len(referenced_cve_ids) + len(products)} "
                f"lookup(s) — {', '.join(fell_back[:5])}; "
                f"{recovered} record(s) recovered from the indexed corpus"
            ),
        )
        return records, [note], len(fell_back)

    def _lookup(
        self,
        query: str,
        *,
        by_id: bool,
        records: dict[str, CveRecord],
        fell_back: list[str],
        reasons: set[str],
    ) -> None:
        """One query against the live feed, degrading to the corpus on failure."""
        if self._source.is_available:
            result = (
                self._source.fetch(query)
                if by_id
                else self._source.search(query, limit=self._results_per_product)
            )
            if result.ok:
                _merge(records, result.records)
                return
            reasons.add(result.failure.reason if result.failure else "unknown")
        else:
            reasons.add("not_configured")

        fell_back.append(query)
        _merge(records, self._from_corpus(query))

    def _from_corpus(self, query: str) -> list[CveRecord]:
        """Recover what the indexed corpus can support for a query.

        Deliberately weaker than the live feed: corpus passages carry an
        identifier, usually a score, and prose — but not machine-readable version
        ranges. Records built here therefore have no ``affected`` ranges, which is
        exactly why they end up as candidates rather than confirmations.
        """
        if self._knowledge is None or not self._knowledge.is_available:
            return []
        chunks = self._knowledge.search(query, limit=_CORPUS_LIMIT)
        return [record for chunk in chunks for record in _records_from_chunk(chunk)]

    # --- Assessment -------------------------------------------------------

    def _assess(
        self, record: CveRecord, assets: Sequence[AssetContext], context: _ThreatContext
    ) -> CveAssessment:
        """Assess one record against the estate and the observed activity."""
        applicability, evidence = assess_applicability(record, assets)
        mapping = _map_to_observed(record, context)
        citations = _citations_for(record)
        return CveAssessment(
            record=record,
            applicability=applicability,
            evidence=evidence,
            exploit_mapping=mapping,
            citations=citations,
            confidence=_assessment_confidence(record, applicability, evidence, mapping),
        )

    @staticmethod
    def _confidence(
        *, assessments: Sequence[CveAssessment], has_inventory: bool, stale: bool
    ) -> float:
        """Applicability certainty, source freshness, and corroboration (EDS §4.4)."""
        if not assessments:
            return 0.0

        mean = sum(item.confidence for item in assessments) / len(assessments)
        if not has_inventory:
            mean *= _NO_INVENTORY_CONFIDENCE
        if stale:
            mean *= _STALE_CONFIDENCE
        return round(min(1.0, max(0.0, mean)), 4)


# --- Threat context ---------------------------------------------------------


class _ThreatContext:
    """The parts of the threat assessment CVE research actually reads."""

    def __init__(
        self,
        *,
        technique_ids: list[str],
        signal_rule_ids: list[str],
        event_ids: list[str],
        terms: set[str],
    ) -> None:
        self.technique_ids = technique_ids
        self.signal_rule_ids = signal_rule_ids
        self.event_ids = event_ids
        self.terms = terms

    @classmethod
    def from_payload(cls, payload: dict[str, object] | None) -> _ThreatContext:
        """Read the assessment defensively: it arrives as serialized state."""
        data: dict[str, Any] = dict(payload or {})
        techniques = [
            str(item.get("technique_id"))
            for item in _as_dicts(data.get("attack_techniques"))
            if item.get("technique_id")
        ]
        signals = _as_dicts(data.get("signals"))
        iocs = _as_dicts(data.get("iocs"))

        terms = {str(ioc.get("value", "")).lower() for ioc in iocs if ioc.get("value")}
        terms |= {str(signal.get("detail", "")).lower() for signal in signals}

        return cls(
            technique_ids=techniques,
            signal_rule_ids=[str(item.get("rule_id")) for item in signals if item.get("rule_id")],
            event_ids=[
                event_id
                for signal in signals
                for event_id in signal.get("event_ids", [])
                if isinstance(event_id, str)
            ],
            terms={term for term in terms if term},
        )


def _map_to_observed(record: CveRecord, context: _ThreatContext) -> ExploitMapping:
    """Link a CVE to observed activity only where something actually connects.

    An empty mapping is the common and correct case: most vulnerabilities on a
    host have nothing to do with the incident being investigated, and inventing a
    connection would turn an inventory finding into a false accusation.
    """
    named = record.cve_id.lower() in " ".join(context.terms)
    product_seen = any(
        products_match(affected.product, term)
        for affected in record.affected
        for term in context.terms
        if len(term) >= 4
    )
    if not (named or product_seen):
        return ExploitMapping()

    rationale = (
        f"{record.cve_id} is named in the observed evidence"
        if named
        else "an affected product appears in the observed indicators"
    )
    return ExploitMapping(
        technique_ids=list(context.technique_ids),
        signal_rule_ids=list(context.signal_rule_ids),
        event_ids=list(context.event_ids),
        rationale=rationale,
    )


def find_cve_ids(text: str) -> list[str]:
    """Collect CVE identifiers named in free text, deduplicated and uppercased.

    Used to pick up identifiers a scanner or an advisory left in the evidence.
    They are *looked up*, never believed: a log line can name any CVE it likes
    (invariant #3).
    """
    found: list[str] = []
    for match in _CVE_ID.findall(text):
        identifier = match.upper()
        if identifier not in found:
            found.append(identifier)
    return found


# --- Records, citations, scoring --------------------------------------------


def _records_from_chunk(chunk: KnowledgeChunk) -> list[CveRecord]:
    """Build corpus-backed records from a retrieved passage.

    One passage can mention several identifiers; each becomes a record carrying
    the passage as its summary. No affected ranges are inferred from prose — that
    is precisely the evidence a cached answer cannot supply.
    """
    identifiers = {match.upper() for match in _CVE_ID.findall(chunk.content)}
    if not identifiers:
        return []

    vector_match = _CVSS_VECTOR.search(chunk.content)
    cvss = interpret(vector_match.group(0)) if vector_match else None
    cwe_ids = sorted({match.upper() for match in _CWE_IN_TEXT.findall(chunk.content)})

    return [
        CveRecord(
            cve_id=cve_id,
            title=cve_id,
            summary=chunk.content.strip(),
            cvss=cvss,
            cwe_ids=cwe_ids,
            source=CveDataSource.KNOWLEDGE_CORPUS,
            stale=True,
        )
        for cve_id in sorted(identifiers)
    ]


def _citations_for(record: CveRecord) -> list[Citation]:
    """Every assessment is cited: the record itself, plus its weakness classes."""
    citations: list[Citation] = []
    if record.source is CveDataSource.NVD:
        citations.append(
            Citation(
                source_id=NVD_SOURCE_ID,
                source=NVD_SOURCE_NAME,
                url=f"{_NVD_DETAIL_URL}/{record.cve_id}",
                title=record.cve_id,
                trust_tier=SourceTrustTier.AUTHORITATIVE,
                published_at=record.published_at,
            )
        )
    else:
        citations.append(
            Citation(
                source_id="knowledge_corpus",
                source="Indexed CVE corpus",
                title=record.cve_id,
                published_at=record.published_at,
            )
        )

    for cwe_id in record.cwe_ids:
        normalized = normalize_cwe_id(cwe_id)
        definition = known_weakness(normalized) if normalized else None
        if definition is not None:
            citations.append(definition.citation())
    return citations


def _assessment_confidence(
    record: CveRecord,
    applicability: CveApplicability,
    evidence: Sequence[ApplicabilityEvidence],
    mapping: ExploitMapping,
) -> float:
    """How sure the agent is about *this* CVE's relevance.

    Confirmed applicability dominates, because it rests on a version comparison
    rather than on a judgement. A candidate's confidence reflects how close it
    came: a host running the product with an unreadable version is a stronger
    lead than a CVE with no published range at all.
    """
    if applicability is CveApplicability.CONFIRMED:
        score = 0.9
    elif applicability is CveApplicability.NOT_APPLICABLE:
        score = 0.8
    else:
        reasons = {item.reason for item in evidence}
        if ApplicabilityReason.VERSION_UNKNOWN in reasons:
            score = 0.5
        elif ApplicabilityReason.VERSION_UNPARSEABLE in reasons:
            score = 0.45
        elif ApplicabilityReason.NO_AFFECTED_RANGE_PUBLISHED in reasons:
            score = 0.35
        else:
            score = 0.3

    if record.stale:
        score *= _STALE_CONFIDENCE
    if record.cvss is None:
        score *= 0.9
    if not mapping.is_empty:
        score = min(1.0, score + 0.05)
    return round(min(1.0, max(0.0, score)), 4)


def _by_severity(assessment: CveAssessment) -> tuple[float, str]:
    """Worst first, then by identifier so ordering is deterministic."""
    score = assessment.record.cvss.base_score if assessment.record.cvss else 0.0
    return (-score, assessment.cve_id)


def _oldest_modification(records: Sequence[CveRecord]) -> datetime | None:
    """How current the *least* current record used was.

    The oldest rather than the newest: freshness is a floor, and reporting the
    newest would let one recently-modified record vouch for a stale dossier.
    """
    stamps = [record.modified_at for record in records if record.modified_at is not None]
    return min(stamps) if stamps else None


def _merge(records: dict[str, CveRecord], found: Sequence[CveRecord]) -> None:
    """Collect records by identifier, preferring live data over cached."""
    for record in found:
        existing = records.get(record.cve_id)
        if existing is None or (existing.stale and not record.stale):
            records[record.cve_id] = record


def _as_dicts(value: object) -> list[dict[str, Any]]:
    """Read a list of mappings out of serialized state, tolerating anything else."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]

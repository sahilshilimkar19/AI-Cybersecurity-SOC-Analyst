"""The Log Analyzer agent (EDS §4.2, SAD §2.1).

Turns raw, heterogeneous log records into a normalized, correlated,
provenance-tagged timeline — and nothing more. The constraint that shapes this
whole module is **structure only, do not infer threats**: this agent establishes
what happened, and the Threat Detector decides what it means. Keeping that line
sharp is what lets a human trust the timeline as evidence rather than as an
opinion.

The pipeline is deliberately deterministic — parse, extract, correlate, score —
because reproducibility is what makes evidence defensible, and because golden
fixtures can only pin behavior that does not drift. The prompt asset is assembled
alongside it so the model-assisted pass (added with the AI layer) inherits the
same contract and the same untrusted-data boundary.

Failure handling is a first-class output, not an exception path:

* an unreadable source becomes a **coverage gap**, and analysis continues;
* an unparseable record is **quarantined**, never silently dropped;
* an uncertain parse lowers that event's **confidence** rather than being hidden.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING

from agents.shared.contracts import AgentDegradation, AgentOutcome
from config.logging import get_logger
from models.logs import (
    CoverageGap,
    CoverageGapKind,
    EntityType,
    LogAnalysisResult,
    NormalizedEvent,
    QuarantinedRecord,
    TimelineEntry,
)
from prompts.assembly import LOG_ANALYZER_PROMPT
from tools.correlation import correlate_events, score_notability
from tools.extraction import extract_entities
from tools.parsers import DEFAULT_PARSERS, parse_record

if TYPE_CHECKING:
    from collections.abc import Sequence

    from integrations.log_sources import LogFetchFailure
    from models.logs import LogAnalysisRequest, RawLogRecord
    from tools.parsers import LogParser

_logger = get_logger(__name__)

AGENT_NAME = "log_analyzer"

# Tools this agent is allow-listed to use (EDS §3.7 least privilege).
ALLOWED_TOOLS = ("parse_record", "extract_entities", "correlate_events", "score_notability")

# How far apart two events can be and still belong to the same episode.
DEFAULT_CORRELATION_WINDOW = timedelta(minutes=30)

# A window is reported as uncovered when this share of it contains no evidence.
_UNCOVERED_RATIO = 0.5


class LogAnalyzer:
    """Normalizes and correlates log records into a timeline."""

    def __init__(
        self,
        *,
        parsers: tuple[LogParser, ...] = DEFAULT_PARSERS,
        correlation_window: timedelta = DEFAULT_CORRELATION_WINDOW,
    ) -> None:
        self._parsers = parsers
        self._correlation_window = correlation_window

    def analyze(
        self,
        request: LogAnalysisRequest,
        *,
        source_failures: Sequence[LogFetchFailure] = (),
    ) -> AgentOutcome[LogAnalysisResult]:
        """Analyze a batch of records, reporting everything it could not do."""
        events: list[NormalizedEvent] = []
        quarantined: list[QuarantinedRecord] = []

        for record in request.records:
            event = self._normalize(record)
            if event is None:
                quarantined.append(
                    QuarantinedRecord(
                        record_id=record.record_id,
                        source_id=record.source_id,
                        reason="unparseable",
                        content=record.content,
                    )
                )
                continue
            events.append(event)

        # Events without a usable timestamp cannot be placed on a timeline; they
        # are retained as evidence but excluded from ordering and correlation.
        events.sort(key=lambda event: (event.event_time, event.event_id))

        correlations = correlate_events(events, window=self._correlation_window)
        timeline = [
            TimelineEntry(
                event_id=event.event_id,
                event_time=event.event_time,
                source_id=event.source_id,
                summary=self._summarize(event),
                notability=event.notability,
            )
            for event in events
        ]

        gaps = self._coverage_gaps(request, events, quarantined, source_failures)
        source_coverage = self._source_coverage(request, events)
        parse_failure_rate = len(quarantined) / len(request.records) if request.records else 0.0
        confidence = self._confidence(events, source_coverage, parse_failure_rate)

        result = LogAnalysisResult(
            investigation_id=request.investigation_id,
            events=events,
            timeline=timeline,
            correlations=correlations,
            coverage_gaps=gaps,
            quarantined=quarantined,
            confidence=confidence,
            source_coverage=round(source_coverage, 4),
            parse_failure_rate=round(parse_failure_rate, 4),
        )

        _logger.info(
            "log_analysis_complete",
            investigation_id=request.investigation_id,
            events=len(events),
            quarantined=len(quarantined),
            correlations=len(correlations),
            coverage_gaps=len(gaps),
            confidence=confidence,
        )

        return AgentOutcome(
            agent=AGENT_NAME,
            output=result,
            confidence=confidence,
            prompt_version=LOG_ANALYZER_PROMPT.version,
            tool_calls=[
                {"tool": "parse_record", "count": len(request.records)},
                {"tool": "extract_entities", "count": len(events)},
                {"tool": "correlate_events", "count": len(correlations)},
            ],
            degradations=[
                AgentDegradation(reason=gap.kind.value, detail=gap.detail) for gap in gaps
            ],
        )

    # --- Internals --------------------------------------------------------

    def _normalize(self, record: RawLogRecord) -> NormalizedEvent | None:
        """Parse one record into a provenance-tagged event, or ``None`` to quarantine."""
        parsed = parse_record(record, parsers=self._parsers)
        if parsed is None:
            return None

        # Without a timestamp the record cannot be placed in the sequence, and an
        # invented time would corrupt the evidence. Fall back to ingestion time
        # and mark the event down, or quarantine if even that is unavailable.
        event_time = parsed.event_time or record.received_at
        if event_time is None:
            return None
        timestamp_inferred = parsed.event_time is None

        entities = extract_entities(
            f"{parsed.message} {record.content}",
            extra=(
                (EntityType.HOST, parsed.host),
                (EntityType.USER, parsed.actor),
                (EntityType.PROCESS, parsed.action if _looks_like_process(parsed.action) else None),
            ),
        )

        confidence = parsed.confidence * (0.6 if timestamp_inferred else 1.0)
        event = NormalizedEvent(
            event_id=_event_id(record),
            record_id=record.record_id,
            source_id=record.source_id,
            source_kind=record.source_kind,
            log_format=parsed.log_format,
            event_time=event_time,
            event_type=parsed.event_type,
            host=parsed.host,
            actor=parsed.actor,
            action=parsed.action,
            outcome=parsed.outcome,
            message=parsed.message,
            entities=entities,
            fields=parsed.fields,
            raw_ref=record.raw_ref,
            confidence=round(confidence, 4),
        )
        return event.model_copy(update={"notability": score_notability(event)})

    @staticmethod
    def _summarize(event: NormalizedEvent) -> str:
        """A short, factual description — no interpretation."""
        actor = event.actor or "unknown actor"
        host = event.host or "unknown host"
        outcome = f" ({event.outcome})" if event.outcome else ""
        return f"{event.event_type.value}{outcome}: {actor} on {host}"

    def _coverage_gaps(
        self,
        request: LogAnalysisRequest,
        events: Sequence[NormalizedEvent],
        quarantined: Sequence[QuarantinedRecord],
        source_failures: Sequence[LogFetchFailure],
    ) -> list[CoverageGap]:
        """Enumerate everything the analysis could not see."""
        gaps: list[CoverageGap] = []

        for failure in source_failures:
            gaps.append(
                CoverageGap(
                    kind=CoverageGapKind.SOURCE_UNAVAILABLE,
                    source_id=failure.source_id,
                    detail=f"{failure.reason}: {failure.detail}".strip(": "),
                )
            )

        seen_sources = {event.source_id for event in events}
        failed_sources = {failure.source_id for failure in source_failures}
        for source_id in request.requested_sources:
            if source_id not in seen_sources and source_id not in failed_sources:
                gaps.append(
                    CoverageGap(
                        kind=CoverageGapKind.SOURCE_EMPTY,
                        source_id=source_id,
                        detail="source returned no usable records",
                    )
                )

        if quarantined:
            by_source: dict[str, int] = {}
            for record in quarantined:
                by_source[record.source_id] = by_source.get(record.source_id, 0) + 1
            gaps.extend(
                CoverageGap(
                    kind=CoverageGapKind.PARSE_FAILURE,
                    source_id=source_id,
                    detail=f"{count} record(s) could not be parsed and were quarantined",
                    affected_records=count,
                )
                for source_id, count in sorted(by_source.items())
            )

        window_gap = self._window_gap(request, events)
        if window_gap is not None:
            gaps.append(window_gap)

        return gaps

    @staticmethod
    def _window_gap(
        request: LogAnalysisRequest, events: Sequence[NormalizedEvent]
    ) -> CoverageGap | None:
        """Report when the requested window is largely devoid of evidence."""
        window = request.time_window
        if window is None:
            return None

        total = (window.end - window.start).total_seconds()
        if total <= 0:
            return None

        in_window = [event for event in events if window.contains(event.event_time)]
        if not in_window:
            return CoverageGap(
                kind=CoverageGapKind.WINDOW_UNCOVERED,
                detail="no events fall within the requested time window",
            )

        observed = (
            max(event.event_time for event in in_window)
            - min(event.event_time for event in in_window)
        ).total_seconds()
        if observed / total < _UNCOVERED_RATIO:
            covered_pct = round(observed / total * 100, 1)
            return CoverageGap(
                kind=CoverageGapKind.WINDOW_UNCOVERED,
                detail=f"evidence covers only {covered_pct}% of the requested window",
            )
        return None

    @staticmethod
    def _source_coverage(request: LogAnalysisRequest, events: Sequence[NormalizedEvent]) -> float:
        """Share of requested sources that produced usable evidence."""
        requested = set(request.requested_sources) or {
            record.source_id for record in request.records
        }
        if not requested:
            return 0.0
        return len({event.source_id for event in events} & requested) / len(requested)

    @staticmethod
    def _confidence(
        events: Sequence[NormalizedEvent], source_coverage: float, parse_failure_rate: float
    ) -> float:
        """Overall confidence from source coverage and parse certainty (EDS §4.2)."""
        if not events:
            return 0.0
        mean_parse_confidence = sum(event.confidence for event in events) / len(events)
        score = mean_parse_confidence * (0.5 + 0.5 * source_coverage) * (1.0 - parse_failure_rate)
        return round(min(1.0, max(0.0, score)), 4)


def _event_id(record: RawLogRecord) -> str:
    """A stable id derived from the record, so re-running yields the same ids."""
    digest = hashlib.sha256(
        f"{record.source_id}|{record.record_id}|{record.content}".encode()
    ).hexdigest()
    return f"evt-{digest[:16]}"


def _looks_like_process(value: str | None) -> bool:
    return bool(value) and "." in str(value)

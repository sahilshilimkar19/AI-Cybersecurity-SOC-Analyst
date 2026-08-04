"""Report assembly: timeline, affected assets, and citation compilation (EDS §4.5).

The deterministic half of reporting. These functions take what the upstream
agents produced and arrange it — they never add to it. Everything that could be
mistaken for a judgement (what the incident *means*, how severe it is) was
decided upstream and is carried through unchanged.

Three properties are worth stating:

* **Truncation is reported, never silent.** A long investigation's timeline is
  bounded so the document stays readable, and the assembler returns how many
  entries it left out so the reporter can say so. A timeline that silently stops
  at fifty entries reads as a complete account of a short incident.
* **Citations are compiled once and numbered stably.** The same source cited from
  three findings is one reference, and its number does not move between
  regenerations of the same report — a report whose ``[3]`` means something
  different on Tuesday is not a citable document.
* **Affected assets are derived from evidence, not asserted.** A host appears
  because events referenced it, and its confirmed CVEs come from applicability
  evidence that named it — so the "affected" list is itself traceable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from models.report import AffectedAsset, ReportTimelineEntry

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from models.logs import NormalizedEvent, TimelineEntry
    from models.values import Citation
    from models.vulnerability import CveAssessment


def assemble_timeline(
    entries: Sequence[TimelineEntry],
    *,
    limit: int,
    events: Sequence[NormalizedEvent] = (),
) -> tuple[list[ReportTimelineEntry], int]:
    """Order and bound the narrative timeline.

    Returns the entries the report will carry and how many were left out. The
    count is not decoration: a reader who cannot tell a complete timeline from a
    truncated one will read the last entry as the end of the incident.

    When truncation is necessary the *most notable* entries are kept rather than
    the first N, because an attack's important moments are rarely its earliest —
    and the retained set is then re-sorted into chronological order so the
    narrative still reads forwards.

    ``events`` supplies the raw references, so each row can be walked back to the
    log line it came from.
    """
    raw_refs = {event.event_id: event.raw_ref for event in events}
    unique: dict[str, TimelineEntry] = {}
    for entry in entries:
        unique.setdefault(entry.event_id, entry)

    ordered = sorted(unique.values(), key=lambda item: (item.event_time, item.event_id))
    omitted = max(0, len(ordered) - limit)
    if omitted:
        kept = sorted(ordered, key=lambda item: (-item.notability, item.event_time, item.event_id))[
            :limit
        ]
        ordered = sorted(kept, key=lambda item: (item.event_time, item.event_id))

    return [
        ReportTimelineEntry(
            event_id=entry.event_id,
            occurred_at=entry.event_time,
            source_id=entry.source_id,
            summary=entry.summary,
            notability=entry.notability,
            raw_ref=raw_refs.get(entry.event_id),
        )
        for entry in ordered
    ], omitted


def collect_affected_assets(
    events: Sequence[NormalizedEvent],
    *,
    confirmed: Sequence[CveAssessment] = (),
    critical_assets: Sequence[str] = (),
) -> list[AffectedAsset]:
    """Derive the affected-asset list from the evidence that named each host.

    Ordered by how much activity each host carried, so the report leads with the
    machine an analyst should look at first.
    """
    critical = {name.lower() for name in critical_assets}
    by_host: dict[str, AffectedAsset] = {}

    for event in events:
        if not event.host:
            continue
        key = event.host.lower()
        existing = by_host.get(key)
        if existing is None:
            by_host[key] = AffectedAsset(
                hostname=event.host,
                event_count=1,
                first_seen=event.event_time,
                last_seen=event.event_time,
                critical=key in critical,
            )
            continue
        by_host[key] = existing.model_copy(
            update={
                "event_count": existing.event_count + 1,
                "first_seen": min(existing.first_seen or event.event_time, event.event_time),
                "last_seen": max(existing.last_seen or event.event_time, event.event_time),
            }
        )

    for assessment in confirmed:
        for item in assessment.evidence:
            if not item.hostname:
                continue
            key = item.hostname.lower()
            asset = by_host.get(key)
            if asset is None:
                asset = AffectedAsset(hostname=item.hostname, critical=key in critical)
            if assessment.cve_id not in asset.confirmed_cve_ids:
                by_host[key] = asset.model_copy(
                    update={"confirmed_cve_ids": [*asset.confirmed_cve_ids, assessment.cve_id]}
                )
            else:
                by_host[key] = asset

    return sorted(
        by_host.values(),
        key=lambda asset: (not asset.critical, -asset.event_count, asset.hostname.lower()),
    )


def compile_citations(*groups: Iterable[Citation]) -> list[Citation]:
    """Merge every cited source into one reference list, deduplicated.

    Order is first-seen, so a regenerated report numbers its references the same
    way — which is what makes ``[3]`` a stable thing to quote.
    """
    seen: set[tuple[str, str]] = set()
    compiled: list[Citation] = []
    for group in groups:
        for citation in group:
            key = citation_key(citation)
            if key in seen:
                continue
            seen.add(key)
            compiled.append(citation)
    return compiled


def citation_key(citation: Citation) -> tuple[str, str]:
    """Identity of a citation: its source plus the exact thing it points at."""
    return (citation.source_id, citation.chunk_id or citation.url or citation.title or "")


def citation_numbers(citations: Sequence[Citation]) -> dict[tuple[str, str], int]:
    """One-based reference numbers for the compiled list."""
    return {citation_key(citation): index for index, citation in enumerate(citations, start=1)}


def reference_marks(citations: Sequence[Citation], numbers: dict[tuple[str, str], int]) -> str:
    """Render a claim's citations as ``[1][4]`` marks, ordered and deduplicated."""
    found = sorted(
        {
            numbers[citation_key(citation)]
            for citation in citations
            if citation_key(citation) in numbers
        }
    )
    return "".join(f"[{number}]" for number in found)

"""Log source connectors (SAD §7, EDS §4.2 required tools).

Every log source sits behind one interface so new sources plug in without agents
knowing the difference. Connectors are **read-only** — they pull evidence and are
never granted write or enforcement authority, consistent with the platform's
assistive posture (SAD §7).

A source that fails does not fail the investigation: the connector returns a
typed failure, the Log Analyzer records a coverage gap, and analysis proceeds
with what is available (EDS §4.2 failure handling). Knowing what you could not
see is part of the evidence.

File and in-memory connectors ship here. Elastic/Splunk query adapters implement
the same protocol and land with the sprints that need live SIEM access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from config.logging import get_logger
from models.logs import LogFormat, LogSourceKind, RawLogRecord, TimeWindow

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

_logger = get_logger(__name__)


@dataclass(frozen=True)
class LogFetchFailure:
    """A source that could not be read, and why."""

    source_id: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class LogFetchResult:
    """What one source returned: records, or a typed failure."""

    source_id: str
    records: tuple[RawLogRecord, ...] = ()
    failure: LogFetchFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None


class LogSource(Protocol):
    """Read-only access to one source of log records."""

    @property
    def source_id(self) -> str: ...
    @property
    def kind(self) -> LogSourceKind: ...
    def fetch(self, window: TimeWindow | None = None) -> LogFetchResult: ...


@dataclass
class InMemoryLogSource:
    """Serves records held in process (tests and fixtures)."""

    source_id_value: str
    kind_value: LogSourceKind = LogSourceKind.FILE
    records: list[RawLogRecord] = field(default_factory=list)
    failure: LogFetchFailure | None = None

    @property
    def source_id(self) -> str:
        return self.source_id_value

    @property
    def kind(self) -> LogSourceKind:
        return self.kind_value

    def fetch(self, window: TimeWindow | None = None) -> LogFetchResult:
        if self.failure is not None:
            return LogFetchResult(source_id=self.source_id, failure=self.failure)
        return LogFetchResult(source_id=self.source_id, records=tuple(self.records))


class FileLogSource:
    """Reads newline-delimited records from a local log file.

    This is the direct-ingestion path for estates without a SIEM, and for
    host-level forensic logs collected during an investigation.
    """

    def __init__(
        self,
        source_id: str,
        path: Path,
        *,
        kind: LogSourceKind = LogSourceKind.FILE,
        declared_format: LogFormat | None = None,
        max_records: int = 100_000,
    ) -> None:
        self._source_id = source_id
        self._path = path
        self._kind = kind
        self._declared_format = declared_format
        self._max_records = max_records

    @property
    def source_id(self) -> str:
        return self._source_id

    @property
    def kind(self) -> LogSourceKind:
        return self._kind

    def fetch(self, window: TimeWindow | None = None) -> LogFetchResult:
        """Read the file, returning a typed failure rather than raising."""
        try:
            text = self._path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _logger.warning(
                "log_source_unreadable", source_id=self._source_id, path=str(self._path)
            )
            return LogFetchResult(
                source_id=self._source_id,
                failure=LogFetchFailure(
                    source_id=self._source_id, reason="unreadable", detail=str(exc)
                ),
            )

        received_at = datetime.now(UTC)
        records = [
            RawLogRecord(
                record_id=f"{self._source_id}:{number}",
                source_id=self._source_id,
                source_kind=self._kind,
                content=line,
                raw_ref=f"{self._path.name}#L{number}",
                received_at=received_at,
                declared_format=self._declared_format,
            )
            for number, line in enumerate(_non_empty_lines(text.splitlines()), start=1)
        ][: self._max_records]

        return LogFetchResult(source_id=self._source_id, records=tuple(records))


def collect(
    sources: Sequence[LogSource], window: TimeWindow | None = None
) -> tuple[list[RawLogRecord], list[LogFetchFailure]]:
    """Fetch every source, isolating failures so one outage costs one source.

    Returns the records gathered and the failures encountered; the caller turns
    the failures into coverage gaps rather than aborting.
    """
    records: list[RawLogRecord] = []
    failures: list[LogFetchFailure] = []

    for source in sources:
        try:
            result = source.fetch(window)
        except Exception as exc:  # pragma: no cover - defensive; connectors return failures
            _logger.warning("log_source_raised", source_id=source.source_id, exc_info=True)
            failures.append(
                LogFetchFailure(source_id=source.source_id, reason="error", detail=str(exc))
            )
            continue

        if result.failure is not None:
            failures.append(result.failure)
            continue
        records.extend(result.records)

    return records, failures


def _non_empty_lines(lines: Iterable[str]) -> Iterable[str]:
    for line in lines:
        if line.strip():
            yield line

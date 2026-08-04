"""Contracts for log analysis (EDS §4.2, SAD §2.1).

The shapes flowing through the Log Analyzer: raw records in, a provenance-tagged
timeline out. Two rules are encoded in these types rather than left to convention:

* **Every normalized event carries provenance** — source, timestamp, and a
  reference back to the raw record. An event that cannot say where it came from
  is not evidence.
* **Log content is untrusted.** ``message`` and ``fields`` hold attacker-
  influenceable text; they are data to be quoted and displayed, never
  instructions to follow (invariant #3).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from models.base import DomainModel


class LogFormat(StrEnum):
    """Wire formats the parsers understand."""

    JSON = "json"
    SYSLOG_RFC3164 = "syslog_rfc3164"
    SYSLOG_RFC5424 = "syslog_rfc5424"
    WINDOWS_EVENT = "windows_event"
    CEF = "cef"
    KEY_VALUE = "key_value"
    UNKNOWN = "unknown"


class LogSourceKind(StrEnum):
    """Where log records come from (SAD §7 log sources)."""

    FILE = "file"
    SYSLOG = "syslog"
    WINDOWS_EVENT_LOG = "windows_event_log"
    SIEM = "siem"


class EventType(StrEnum):
    """Normalized security-event categories.

    Deliberately descriptive, not judgmental: the Log Analyzer structures
    evidence and must not infer threats (EDS §4.2 validation rules).
    """

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    PRIVILEGE_CHANGE = "privilege_change"
    PROCESS_START = "process_start"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    SERVICE_CONTROL = "service_control"
    ACCOUNT_CHANGE = "account_change"
    CONFIGURATION_CHANGE = "configuration_change"
    OTHER = "other"


class EntityType(StrEnum):
    """Entities extracted from log content, used to correlate across sources."""

    HOST = "host"
    USER = "user"
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    PROCESS = "process"


class CorrelationKind(StrEnum):
    """Why a set of events was grouped together."""

    SHARED_HOST = "shared_host"
    SHARED_ACTOR = "shared_actor"
    SHARED_ADDRESS = "shared_address"
    SHARED_PROCESS = "shared_process"


class CoverageGapKind(StrEnum):
    """Why part of the evidence picture is missing.

    Gaps are reported, never hidden: an investigation must know what it could
    not see (EDS §4.2 failure handling).
    """

    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_EMPTY = "source_empty"
    PARSE_FAILURE = "parse_failure"
    WINDOW_UNCOVERED = "window_uncovered"


class TimeWindow(DomainModel):
    """The investigation's time bounds."""

    start: datetime
    end: datetime

    def contains(self, moment: datetime) -> bool:
        """Whether a timestamp falls inside the window (inclusive)."""
        return self.start <= moment <= self.end


class RawLogRecord(DomainModel):
    """One unparsed record with the metadata of where it came from."""

    record_id: str
    source_id: str
    source_kind: LogSourceKind
    content: str
    # Object-store pointer to the immutable original, so a normalized event can
    # always be traced back to exactly what was ingested.
    raw_ref: str | None = None
    received_at: datetime | None = None
    declared_format: LogFormat | None = None


class Entity(DomainModel):
    """An identifier extracted from a record."""

    type: EntityType
    value: str


class NormalizedEvent(DomainModel):
    """A parsed, provenance-tagged security event."""

    event_id: str
    record_id: str
    source_id: str
    source_kind: LogSourceKind
    log_format: LogFormat
    event_time: datetime
    event_type: EventType = EventType.OTHER
    host: str | None = None
    actor: str | None = None
    action: str | None = None
    outcome: str | None = None
    # Untrusted: the original message text, retained verbatim for the analyst.
    message: str = ""
    entities: list[Entity] = Field(default_factory=list)
    fields: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str | None = None
    # How interesting the event is for triage (0..1), and how sure the parser is.
    notability: float = 0.0
    confidence: float = 1.0


class QuarantinedRecord(DomainModel):
    """A record that could not be parsed. Retained, never dropped."""

    record_id: str
    source_id: str
    reason: str
    content: str


class TimelineEntry(DomainModel):
    """One ordered step in the reconstructed sequence of activity."""

    event_id: str
    event_time: datetime
    source_id: str
    summary: str
    notability: float = 0.0


class Correlation(DomainModel):
    """A set of events linked by a shared entity within the time window."""

    correlation_id: str
    kind: CorrelationKind
    key: str
    event_ids: list[str] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    rationale: str = ""


class CoverageGap(DomainModel):
    """Something the analysis could not see, and why."""

    kind: CoverageGapKind
    source_id: str | None = None
    detail: str = ""
    affected_records: int = 0


class LogAnalysisRequest(DomainModel):
    """Input to the Log Analyzer (EDS §4.2 input schema)."""

    investigation_id: str
    records: list[RawLogRecord] = Field(default_factory=list)
    time_window: TimeWindow | None = None
    scope: list[str] = Field(default_factory=list)
    # Sources that were asked for, so silence can be distinguished from absence.
    requested_sources: list[str] = Field(default_factory=list)
    prior_correlation_ref: str | None = None


class LogAnalysisResult(DomainModel):
    """Output of the Log Analyzer (EDS §4.2 output schema)."""

    investigation_id: str
    events: list[NormalizedEvent] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)
    quarantined: list[QuarantinedRecord] = Field(default_factory=list)
    confidence: float = 0.0
    source_coverage: float = 0.0
    parse_failure_rate: float = 0.0

    @property
    def has_gaps(self) -> bool:
        """Whether anything was missing from the evidence picture."""
        return bool(self.coverage_gaps)

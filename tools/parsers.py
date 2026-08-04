"""Log parsers and normalizers (EDS §4.2 required tools).

Real estates emit logs in several shapes at once, so parsing is a chain of
format-specific parsers tried in order of specificity, ending in a fallback that
still produces a usable event rather than discarding the line.

Nothing here infers threats. A parser decides *what happened* (an authentication
failed, a process started) and never *whether it was malicious* — that separation
is the Log Analyzer's core constraint (EDS §4.2) and it is why these functions are
deterministic and independently testable.

A record that cannot be parsed at all is **quarantined, not dropped**: silently
discarding evidence would leave an investigation confidently blind.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from models.logs import EventType, LogFormat

if TYPE_CHECKING:
    from models.logs import RawLogRecord

# --- Shared vocabulary ------------------------------------------------------

# Keys different products use for the same idea. Normalizing these is most of
# what "normalization" means in practice.
_HOST_KEYS = ("host", "hostname", "computer", "computer_name", "device", "src_host", "machine")
_ACTOR_KEYS = ("user", "username", "account", "actor", "subject_user_name", "target_user_name")
_ACTION_KEYS = ("action", "event", "event_type", "activity", "operation", "task")
_OUTCOME_KEYS = ("outcome", "result", "status", "success")
_MESSAGE_KEYS = ("message", "msg", "description", "text", "event_data", "detail")
_TIME_KEYS = ("timestamp", "time", "@timestamp", "event_time", "time_created", "date")

_SYSLOG_MONTHS = {
    month: index
    for index, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

# Event-type classification. Ordered: the first pattern that matches wins, so
# more specific phrases must precede general ones.
_EVENT_TYPE_PATTERNS: tuple[tuple[EventType, re.Pattern[str]], ...] = (
    (
        EventType.AUTH_FAILURE,
        re.compile(
            r"\b(failed\s+password|authentication\s+fail\w*|login\s+fail\w*|invalid\s+user"
            r"|failed\s+login|logon\s+fail\w*|access\s+denied)\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.AUTH_SUCCESS,
        re.compile(
            r"\b(accepted\s+password|authentication\s+succe\w*|login\s+succe\w*"
            r"|successful\s+logon|session\s+opened|logged\s+in)\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.PRIVILEGE_CHANGE,
        re.compile(
            r"\b(sudo|privilege|elevat\w+|special\s+privileges|runas|administrator\s+rights)\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.ACCOUNT_CHANGE,
        re.compile(
            r"\b(user\s+added|account\s+(created|deleted|enabled|disabled|locked)"
            r"|password\s+(changed|reset)|group\s+member(ship)?\s+(added|removed))\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.PROCESS_START,
        re.compile(
            r"\b(process\s+(creat\w+|start\w+|launch\w+)|new\s+process|command\s+line|exec\w*)\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.NETWORK_CONNECTION,
        re.compile(
            r"\b(connection\s+(from|to|establish\w+|accepted)|outbound|inbound|network\s+connect\w*"
            r"|tcp|udp|dns\s+quer\w+)\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.SERVICE_CONTROL,
        re.compile(
            r"\b(service\s+(start\w*|stop\w*|install\w*|creat\w*)|daemon\s+(start\w*|stop\w*))\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.FILE_ACCESS,
        re.compile(
            r"\b(file\s+(read|written|created|deleted|access\w*)|object\s+access"
            r"|directory\s+access)\b",
            re.IGNORECASE,
        ),
    ),
    (
        EventType.CONFIGURATION_CHANGE,
        re.compile(
            r"\b(config\w*\s+(chang\w+|modif\w+|updat\w+)|registry\s+(value|key)\s+(set|modif\w+)"
            r"|policy\s+chang\w+)\b",
            re.IGNORECASE,
        ),
    ),
)

# Windows Security event IDs worth naming explicitly; IDs are unambiguous where
# free text is not, so they take precedence over message matching.
_WINDOWS_EVENT_IDS: dict[int, EventType] = {
    4624: EventType.AUTH_SUCCESS,
    4625: EventType.AUTH_FAILURE,
    4634: EventType.AUTH_SUCCESS,
    4648: EventType.AUTH_SUCCESS,
    4672: EventType.PRIVILEGE_CHANGE,
    4673: EventType.PRIVILEGE_CHANGE,
    4688: EventType.PROCESS_START,
    4720: EventType.ACCOUNT_CHANGE,
    4722: EventType.ACCOUNT_CHANGE,
    4724: EventType.ACCOUNT_CHANGE,
    4728: EventType.ACCOUNT_CHANGE,
    4732: EventType.ACCOUNT_CHANGE,
    4740: EventType.ACCOUNT_CHANGE,
    7045: EventType.SERVICE_CONTROL,
}


class ParsedRecord:
    """The normalized shape every parser produces."""

    __slots__ = (
        "action",
        "actor",
        "confidence",
        "event_time",
        "event_type",
        "fields",
        "host",
        "log_format",
        "message",
        "outcome",
    )

    def __init__(
        self,
        *,
        log_format: LogFormat,
        event_time: datetime | None,
        message: str,
        host: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        event_type: EventType = EventType.OTHER,
        fields: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> None:
        self.log_format = log_format
        self.event_time = event_time
        self.message = message
        self.host = host
        self.actor = actor
        self.action = action
        self.outcome = outcome
        self.event_type = event_type
        self.fields = fields or {}
        self.confidence = confidence


class LogParser(Protocol):
    """Recognizes and parses one log format.

    ``reference_time`` supplies the context some formats need but do not carry —
    most importantly the year, which RFC 3164 syslog omits entirely.
    """

    @property
    def log_format(self) -> LogFormat: ...
    def can_parse(self, content: str) -> bool: ...
    def parse(
        self, content: str, reference_time: datetime | None = None
    ) -> ParsedRecord | None: ...


# --- Helpers ---------------------------------------------------------------


def _normalize_key(key: str) -> str:
    """Fold a field name to a comparable form.

    Products spell the same field as ``TimeCreated``, ``time_created``, and
    ``time-created``; matching on a folded key means one alias list covers all of
    them instead of silently missing two thirds of the shapes in the wild.
    """
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _first(payload: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    """Return the first present, non-empty value among ``keys`` (alias-insensitive)."""
    folded = {_normalize_key(str(key)): value for key, value in payload.items()}
    for key in keys:
        value = folded.get(_normalize_key(key))
        if value not in (None, ""):
            return value
    return None


def parse_timestamp(value: Any, *, reference_year: int | None = None) -> datetime | None:
    """Parse the timestamp shapes log sources actually emit.

    Returns ``None`` rather than guessing when the value is unrecognizable; the
    caller then flags reduced confidence instead of inventing a time.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        # Heuristic: values past ~2001 in milliseconds are milliseconds.
        seconds = float(value) / 1000.0 if value > 100_000_000_000 else float(value)
        return datetime.fromtimestamp(seconds, tz=UTC)
    if not isinstance(value, str) or not value.strip():
        return None

    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is not None:
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    # RFC 3164 syslog: "Oct  7 12:34:56" — no year, so the caller supplies one.
    match = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", text)
    if match:
        month = _SYSLOG_MONTHS.get(match.group(1))
        if month:
            year = reference_year or datetime.now(UTC).year
            return datetime(
                year,
                month,
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                int(match.group(5)),
                tzinfo=UTC,
            )
    return None


def classify_event_type(text: str, fields: dict[str, Any] | None = None) -> EventType:
    """Classify an event from its identifiers first, then its text.

    Identifier-driven classification is preferred because a Windows event id is
    unambiguous where prose is not.
    """
    if fields:
        raw_id = _first(fields, ("event_id", "eventid", "id"))
        try:
            event_id = int(str(raw_id))
        except (TypeError, ValueError):
            event_id = 0
        if event_id in _WINDOWS_EVENT_IDS:
            return _WINDOWS_EVENT_IDS[event_id]

    for event_type, pattern in _EVENT_TYPE_PATTERNS:
        if pattern.search(text):
            return event_type
    return EventType.OTHER


def _outcome_from(text: str, explicit: Any | None) -> str | None:
    if explicit is not None:
        return str(explicit)
    lowered = text.lower()
    if re.search(r"\b(fail\w*|denied|invalid|error|unauthorized)\b", lowered):
        return "failure"
    if re.search(r"\b(success\w*|accepted|granted|allowed)\b", lowered):
        return "success"
    return None


# --- Parsers ---------------------------------------------------------------


class JsonLogParser:
    """Structured JSON records — the easy case, and increasingly the common one."""

    @property
    def log_format(self) -> LogFormat:
        return LogFormat.JSON

    def can_parse(self, content: str) -> bool:
        text = content.strip()
        return text.startswith("{") and text.endswith("}")

    def parse(self, content: str, reference_time: datetime | None = None) -> ParsedRecord | None:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None

        message = str(_first(payload, _MESSAGE_KEYS) or content)
        event_time = parse_timestamp(_first(payload, _TIME_KEYS))
        return ParsedRecord(
            log_format=LogFormat.JSON,
            event_time=event_time,
            message=message,
            host=_optional_str(_first(payload, _HOST_KEYS)),
            actor=_optional_str(_first(payload, _ACTOR_KEYS)),
            action=_optional_str(_first(payload, _ACTION_KEYS)),
            outcome=_outcome_from(message, _first(payload, _OUTCOME_KEYS)),
            event_type=classify_event_type(
                f"{message} {_first(payload, _ACTION_KEYS) or ''}", payload
            ),
            fields=payload,
            # A record without a usable timestamp cannot be placed on the
            # timeline reliably, so it is explicitly less trustworthy.
            confidence=1.0 if event_time else 0.5,
        )


class WindowsEventParser:
    """Windows Event Log records exported as JSON.

    Recognized by their distinctive envelope (``EventID`` plus ``Channel`` or
    ``Provider``) rather than by content, so they are classified by event id.
    """

    @property
    def log_format(self) -> LogFormat:
        return LogFormat.WINDOWS_EVENT

    def can_parse(self, content: str) -> bool:
        text = content.strip()
        if not (text.startswith("{") and text.endswith("}")):
            return False
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return False
        if not isinstance(payload, dict):
            return False
        lowered = {str(key).lower() for key in payload}
        return "eventid" in lowered and bool(lowered & {"channel", "provider", "providername"})

    def parse(self, content: str, reference_time: datetime | None = None) -> ParsedRecord | None:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None

        message = str(_first(payload, _MESSAGE_KEYS) or "")
        event_time = parse_timestamp(_first(payload, _TIME_KEYS))
        event_type = classify_event_type(message, payload)
        return ParsedRecord(
            log_format=LogFormat.WINDOWS_EVENT,
            event_time=event_time,
            message=message or f"Windows event {_first(payload, ('event_id', 'eventid')) or '?'}",
            host=_optional_str(_first(payload, _HOST_KEYS)),
            actor=_optional_str(_first(payload, _ACTOR_KEYS)),
            action=_optional_str(_first(payload, ("task", "opcode", *_ACTION_KEYS))),
            outcome=_outcome_from(message, _first(payload, _OUTCOME_KEYS)),
            event_type=event_type,
            fields=payload,
            confidence=1.0 if event_time else 0.5,
        )


class SyslogRfc5424Parser:
    """RFC 5424 syslog: ``<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG``."""

    _PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
        r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$"
    )

    @property
    def log_format(self) -> LogFormat:
        return LogFormat.SYSLOG_RFC5424

    def can_parse(self, content: str) -> bool:
        return bool(self._PATTERN.match(content.strip()))

    def parse(self, content: str, reference_time: datetime | None = None) -> ParsedRecord | None:
        match = self._PATTERN.match(content.strip())
        if not match:
            return None

        rest = match.group("rest").strip()
        # Strip structured data, keeping it as a field rather than discarding it.
        structured, message = _split_structured_data(rest)
        event_time = parse_timestamp(match.group("ts"))
        host = _none_if_nil(match.group("host"))
        app = _none_if_nil(match.group("app"))

        fields: dict[str, Any] = {
            "priority": int(match.group("pri")),
            "version": match.group("version"),
            "app_name": app,
            "proc_id": _none_if_nil(match.group("procid")),
            "msg_id": _none_if_nil(match.group("msgid")),
        }
        if structured:
            fields["structured_data"] = structured

        return ParsedRecord(
            log_format=LogFormat.SYSLOG_RFC5424,
            event_time=event_time,
            message=message,
            host=host,
            actor=_actor_from_message(message),
            action=app,
            outcome=_outcome_from(message, None),
            event_type=classify_event_type(message),
            fields=fields,
            confidence=1.0 if event_time else 0.5,
        )


class SyslogRfc3164Parser:
    """RFC 3164 syslog: ``<PRI>MMM DD HH:MM:SS HOST TAG: MSG`` (the classic shape)."""

    _PATTERN = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
    )

    @property
    def log_format(self) -> LogFormat:
        return LogFormat.SYSLOG_RFC3164

    def can_parse(self, content: str) -> bool:
        return bool(self._PATTERN.match(content.strip()))

    def parse(self, content: str, reference_time: datetime | None = None) -> ParsedRecord | None:
        match = self._PATTERN.match(content.strip())
        if not match:
            return None

        message = match.group("msg")
        # RFC 3164 omits the year. Inferring it from when the record was ingested
        # is right; inferring it from the wall clock would silently misdate every
        # historical log replayed into an investigation.
        event_time = parse_timestamp(
            match.group("ts"),
            reference_year=reference_time.year if reference_time else None,
        )
        fields: dict[str, Any] = {"tag": match.group("tag")}
        if match.group("pri"):
            fields["priority"] = int(match.group("pri"))
        if match.group("pid"):
            fields["pid"] = int(match.group("pid"))

        return ParsedRecord(
            log_format=LogFormat.SYSLOG_RFC3164,
            event_time=event_time,
            message=message,
            host=match.group("host"),
            actor=_actor_from_message(message),
            action=match.group("tag"),
            outcome=_outcome_from(message, None),
            event_type=classify_event_type(message),
            fields=fields,
            # The year is absent from the wire format and must be inferred, so
            # these timestamps are inherently slightly less certain.
            confidence=0.9 if event_time else 0.5,
        )


class CefParser:
    """ArcSight CEF: ``CEF:0|Vendor|Product|Version|SigID|Name|Severity|ext``."""

    _PREFIX = re.compile(r"^CEF:\d+\|")

    @property
    def log_format(self) -> LogFormat:
        return LogFormat.CEF

    def can_parse(self, content: str) -> bool:
        return bool(self._PREFIX.match(content.strip()))

    def parse(self, content: str, reference_time: datetime | None = None) -> ParsedRecord | None:
        text = content.strip()
        if not self._PREFIX.match(text):
            return None

        # CEF has exactly seven header fields before the key=value extension.
        parts = text.split("|", 7)
        if len(parts) < 8:
            return None

        _, vendor, product, version, signature, name, severity, extension = parts
        fields: dict[str, Any] = {
            "vendor": vendor,
            "product": product,
            "device_version": version,
            "signature_id": signature,
            "name": name,
            "cef_severity": severity,
        }
        fields.update(_parse_key_values(extension))

        message = str(fields.get("msg") or name)
        return ParsedRecord(
            log_format=LogFormat.CEF,
            event_time=parse_timestamp(_first(fields, ("rt", *_TIME_KEYS))),
            message=message,
            host=_optional_str(_first(fields, ("dvchost", "dhost", "shost", *_HOST_KEYS))),
            actor=_optional_str(_first(fields, ("duser", "suser", *_ACTOR_KEYS))),
            action=name,
            outcome=_outcome_from(f"{name} {message}", fields.get("outcome")),
            event_type=classify_event_type(f"{name} {message}", fields),
            fields=fields,
            confidence=1.0 if _first(fields, ("rt", *_TIME_KEYS)) else 0.5,
        )


class KeyValueParser:
    """Loose ``key=value`` lines, common in appliance and firewall logs."""

    _PAIR = re.compile(r"\b[\w.\-]+=")

    @property
    def log_format(self) -> LogFormat:
        return LogFormat.KEY_VALUE

    def can_parse(self, content: str) -> bool:
        # Require a couple of pairs so ordinary prose containing "=" is not
        # mistaken for a structured record.
        return len(self._PAIR.findall(content)) >= 2

    def parse(self, content: str, reference_time: datetime | None = None) -> ParsedRecord | None:
        fields = _parse_key_values(content)
        if not fields:
            return None

        message = str(_first(fields, _MESSAGE_KEYS) or content.strip())
        event_time = parse_timestamp(_first(fields, _TIME_KEYS))
        return ParsedRecord(
            log_format=LogFormat.KEY_VALUE,
            event_time=event_time,
            message=message,
            host=_optional_str(_first(fields, _HOST_KEYS)),
            actor=_optional_str(_first(fields, _ACTOR_KEYS)),
            action=_optional_str(_first(fields, _ACTION_KEYS)),
            outcome=_outcome_from(content, _first(fields, _OUTCOME_KEYS)),
            event_type=classify_event_type(content, fields),
            fields=fields,
            confidence=0.8 if event_time else 0.4,
        )


# Ordered most specific first: Windows before generic JSON, RFC 5424 before the
# looser 3164, structured formats before the key=value catch-all.
DEFAULT_PARSERS: tuple[LogParser, ...] = (
    WindowsEventParser(),
    JsonLogParser(),
    SyslogRfc5424Parser(),
    SyslogRfc3164Parser(),
    CefParser(),
    KeyValueParser(),
)


def parse_record(
    record: RawLogRecord, *, parsers: tuple[LogParser, ...] = DEFAULT_PARSERS
) -> ParsedRecord | None:
    """Parse a record with the first parser that recognizes it.

    A declared format is honored first when it is available and works, since the
    source knows its own shape better than sniffing does. The record's ingestion
    time is passed down as the reference for formats that omit the year.
    """
    content = record.content.strip()
    if not content:
        return None

    reference_time = record.received_at

    if record.declared_format is not None:
        for parser in parsers:
            if parser.log_format is record.declared_format:
                parsed = parser.parse(content, reference_time)
                if parsed is not None:
                    return parsed
                break

    for parser in parsers:
        if parser.can_parse(content):
            parsed = parser.parse(content, reference_time)
            if parsed is not None:
                return parsed
    return None


# --- Small helpers ---------------------------------------------------------


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _none_if_nil(value: str) -> str | None:
    """RFC 5424 uses ``-`` for an absent field."""
    return None if value == "-" else value


def _actor_from_message(message: str) -> str | None:
    """Pull a username out of common syslog phrasings ("for user bob", "user=bob")."""
    match = re.search(
        r"\bfor\s+(?:invalid\s+user\s+)?(?P<user>[\w.\-$]+)\s+from\b", message, re.IGNORECASE
    )
    if match:
        return match.group("user")
    match = re.search(r"\buser[=\s]+(?P<user>[\w.\-$]+)", message, re.IGNORECASE)
    return match.group("user") if match else None


def _parse_key_values(text: str) -> dict[str, Any]:
    """Parse ``key=value`` pairs, honoring quoted values."""
    fields: dict[str, Any] = {}
    for match in re.finditer(
        r"([\w.\-]+)=(\"[^\"]*\"|'[^']*'|[^\s]*)",
        text,
    ):
        key = match.group(1).lower()
        value = match.group(2).strip("\"'")
        fields[key] = value
    return fields


def _split_structured_data(rest: str) -> tuple[str | None, str]:
    """Separate RFC 5424 structured data from the human-readable message."""
    if rest.startswith("-"):
        return None, rest[1:].strip()
    if not rest.startswith("["):
        return None, rest
    depth = 0
    for index, char in enumerate(rest):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return rest[: index + 1], rest[index + 1 :].strip()
    return None, rest

"""Golden-fixture tests across log formats (EDS §4.2 testing strategy).

Each case is a real-shaped line from the format it exercises, pinned to the
normalized fields it must produce. These are the regression net for parsing: log
formats are the most variable input the platform takes, and a silent parsing
regression would degrade every downstream agent at once.
"""

from datetime import UTC, datetime

import pytest

from models.logs import EventType, LogFormat, LogSourceKind, RawLogRecord
from tools.parsers import (
    CefParser,
    JsonLogParser,
    KeyValueParser,
    SyslogRfc3164Parser,
    SyslogRfc5424Parser,
    WindowsEventParser,
    classify_event_type,
    parse_record,
    parse_timestamp,
)

INGESTED_AT = datetime(2024, 10, 7, 12, 45, tzinfo=UTC)


def _record(content: str, **kwargs: object) -> RawLogRecord:
    payload: dict[str, object] = {
        "record_id": "r1",
        "source_id": "hostlogs",
        "source_kind": LogSourceKind.FILE,
        "content": content,
        "received_at": INGESTED_AT,
    }
    payload.update(kwargs)
    return RawLogRecord.model_validate(payload)


# --- Timestamps ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2024-10-07T12:36:00Z", datetime(2024, 10, 7, 12, 36, tzinfo=UTC)),
        ("2024-10-07T12:36:00+00:00", datetime(2024, 10, 7, 12, 36, tzinfo=UTC)),
        (1_728_304_560, datetime(2024, 10, 7, 12, 36, tzinfo=UTC)),
        (1_728_304_560_000, datetime(2024, 10, 7, 12, 36, tzinfo=UTC)),
    ],
)
def test_parse_timestamp_handles_common_shapes(value: object, expected: datetime) -> None:
    assert parse_timestamp(value) == expected


def test_naive_timestamps_are_treated_as_utc() -> None:
    parsed = parse_timestamp("2024-10-07T12:36:00")
    assert parsed is not None
    assert parsed.tzinfo is not None


def test_unrecognizable_timestamp_returns_none_rather_than_guessing() -> None:
    assert parse_timestamp("not a time") is None
    assert parse_timestamp(None) is None
    assert parse_timestamp("") is None


def test_syslog_timestamp_uses_the_supplied_reference_year() -> None:
    """RFC 3164 omits the year; it must come from ingestion, not the wall clock."""
    parsed = parse_timestamp("Oct  7 12:34:56", reference_year=2024)
    assert parsed == datetime(2024, 10, 7, 12, 34, 56, tzinfo=UTC)


# --- Per-format golden fixtures -------------------------------------------


def test_syslog_rfc3164_is_parsed() -> None:
    line = (
        "Oct  7 12:34:56 web-01 sshd[1234]: Failed password for invalid user admin "
        "from 203.0.113.9 port 22 ssh2"
    )
    assert SyslogRfc3164Parser().can_parse(line)

    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.log_format is LogFormat.SYSLOG_RFC3164
    assert parsed.event_time == datetime(2024, 10, 7, 12, 34, 56, tzinfo=UTC)
    assert parsed.host == "web-01"
    assert parsed.actor == "admin"
    assert parsed.action == "sshd"
    assert parsed.event_type is EventType.AUTH_FAILURE
    assert parsed.outcome == "failure"
    assert parsed.fields["pid"] == 1234


def test_syslog_rfc5424_is_parsed() -> None:
    line = (
        "<165>1 2024-10-07T12:35:10Z web-01 sshd 1235 ID47 "
        "[exampleSDID@32473 iut=3] Accepted password for deploy from 203.0.113.9"
    )
    assert SyslogRfc5424Parser().can_parse(line)

    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.log_format is LogFormat.SYSLOG_RFC5424
    assert parsed.event_time == datetime(2024, 10, 7, 12, 35, 10, tzinfo=UTC)
    assert parsed.host == "web-01"
    assert parsed.actor == "deploy"
    assert parsed.event_type is EventType.AUTH_SUCCESS
    assert parsed.fields["priority"] == 165
    # Structured data is retained as a field, not discarded.
    assert "exampleSDID" in str(parsed.fields["structured_data"])
    assert "Accepted password" in parsed.message


def test_rfc5424_nil_fields_become_none() -> None:
    parsed = SyslogRfc5424Parser().parse("<34>1 2024-10-07T12:00:00Z - - - - - hello")
    assert parsed is not None
    assert parsed.host is None
    assert parsed.fields["app_name"] is None


def test_json_log_is_parsed() -> None:
    line = (
        '{"timestamp":"2024-10-07T12:36:00Z","host":"web-01","user":"deploy",'
        '"action":"process_create","message":"New process created: powershell.exe"}'
    )
    assert JsonLogParser().can_parse(line)

    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.log_format is LogFormat.JSON
    assert parsed.host == "web-01"
    assert parsed.actor == "deploy"
    assert parsed.event_type is EventType.PROCESS_START
    assert parsed.confidence == 1.0


def test_windows_event_is_parsed_and_classified_by_event_id() -> None:
    line = (
        '{"EventID":4625,"Channel":"Security","Computer":"win-02",'
        '"TimeCreated":"2024-10-07T12:37:00Z","TargetUserName":"administrator",'
        '"Message":"An account failed to log on."}'
    )
    assert WindowsEventParser().can_parse(line)

    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.log_format is LogFormat.WINDOWS_EVENT
    # CamelCase field names must resolve to the same normalized fields.
    assert parsed.event_time == datetime(2024, 10, 7, 12, 37, tzinfo=UTC)
    assert parsed.host == "win-02"
    assert parsed.actor == "administrator"
    assert parsed.event_type is EventType.AUTH_FAILURE


def test_windows_event_id_beats_message_text() -> None:
    """An event id is unambiguous where prose is not, so it wins."""
    line = (
        '{"EventID":4688,"Provider":"Microsoft-Windows-Security-Auditing",'
        '"Computer":"win-02","TimeCreated":"2024-10-07T12:38:00Z",'
        '"Message":"authentication failure mentioned in passing"}'
    )
    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.event_type is EventType.PROCESS_START


def test_cef_is_parsed() -> None:
    line = (
        "CEF:0|Vendor|FW|1.0|100|Blocked connection|5|"
        "src=203.0.113.9 dst=10.0.0.5 duser=deploy rt=2024-10-07T12:38:00Z "
        'msg="outbound connection to evil.example.com"'
    )
    assert CefParser().can_parse(line)

    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.log_format is LogFormat.CEF
    assert parsed.event_time == datetime(2024, 10, 7, 12, 38, tzinfo=UTC)
    assert parsed.actor == "deploy"
    assert parsed.fields["vendor"] == "Vendor"
    assert parsed.fields["signature_id"] == "100"
    assert parsed.event_type is EventType.NETWORK_CONNECTION


def test_key_value_is_parsed() -> None:
    line = (
        "time=2024-10-07T12:39:00Z host=web-01 user=deploy action=file_access "
        "path=/etc/shadow result=denied"
    )
    assert KeyValueParser().can_parse(line)

    parsed = parse_record(_record(line))
    assert parsed is not None
    assert parsed.log_format is LogFormat.KEY_VALUE
    assert parsed.host == "web-01"
    assert parsed.actor == "deploy"
    assert parsed.outcome == "denied"


def test_prose_containing_an_equals_sign_is_not_treated_as_key_value() -> None:
    assert not KeyValueParser().can_parse("the config value = 5 was observed")


# --- Format selection and failure -----------------------------------------


def test_declared_format_is_preferred_over_sniffing() -> None:
    line = '{"timestamp":"2024-10-07T12:36:00Z","host":"web-01","message":"hello"}'
    parsed = parse_record(_record(line, declared_format=LogFormat.JSON))
    assert parsed is not None
    assert parsed.log_format is LogFormat.JSON


def test_a_wrong_declared_format_falls_back_to_sniffing() -> None:
    """A source that mislabels itself must not cost us the record."""
    line = "Oct  7 12:34:56 web-01 sshd[1]: Accepted password for deploy from 10.0.0.1"
    parsed = parse_record(_record(line, declared_format=LogFormat.CEF))
    assert parsed is not None
    assert parsed.log_format is LogFormat.SYSLOG_RFC3164


def test_unparseable_content_returns_none() -> None:
    assert parse_record(_record("!!!! not a log line &&&")) is None


def test_empty_content_returns_none() -> None:
    assert parse_record(_record("   ")) is None


def test_malformed_json_is_not_accepted_as_json() -> None:
    assert JsonLogParser().parse('{"broken": ') is None


def test_json_array_is_not_accepted_as_a_record() -> None:
    assert JsonLogParser().parse("[1, 2, 3]") is None


# --- Classification --------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Failed password for root", EventType.AUTH_FAILURE),
        ("Accepted password for deploy", EventType.AUTH_SUCCESS),
        ("sudo: deploy : command not allowed", EventType.PRIVILEGE_CHANGE),
        ("New process created", EventType.PROCESS_START),
        ("outbound connection to host", EventType.NETWORK_CONNECTION),
        ("service started successfully", EventType.SERVICE_CONTROL),
        ("user added to group", EventType.ACCOUNT_CHANGE),
        ("object access attempted", EventType.FILE_ACCESS),
        ("policy changed by admin", EventType.CONFIGURATION_CHANGE),
        ("nothing of note here", EventType.OTHER),
    ],
)
def test_event_classification(text: str, expected: EventType) -> None:
    assert classify_event_type(text) is expected


def test_classification_never_asserts_maliciousness() -> None:
    """Structure only: even overtly hostile text classifies by action, not verdict."""
    assert classify_event_type("malware ransomware attack detected") is EventType.OTHER

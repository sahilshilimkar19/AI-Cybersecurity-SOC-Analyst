"""Tests for log source connectors: read-only, failure-isolating."""

from pathlib import Path

from integrations.log_sources import (
    FileLogSource,
    InMemoryLogSource,
    LogFetchFailure,
    LogFetchResult,
    collect,
)
from models.logs import LogFormat, LogSourceKind, RawLogRecord, TimeWindow


def _record(record_id: str = "r1") -> RawLogRecord:
    return RawLogRecord(
        record_id=record_id,
        source_id="hostlogs",
        source_kind=LogSourceKind.FILE,
        content="Oct  7 12:34:56 web-01 sshd[1]: Accepted password for deploy from 10.0.0.1",
    )


def test_file_source_reads_lines_with_provenance(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("line one\nline two\n\nline three\n", encoding="utf-8")

    result = FileLogSource("hostlogs", path).fetch()

    assert result.ok
    assert [record.content for record in result.records] == ["line one", "line two", "line three"]
    # Every record can be traced back to its exact position in the file.
    assert [record.raw_ref for record in result.records] == [
        "auth.log#L1",
        "auth.log#L2",
        "auth.log#L3",
    ]
    assert all(record.received_at is not None for record in result.records)


def test_file_source_records_its_declared_format(tmp_path: Path) -> None:
    path = tmp_path / "app.json"
    path.write_text('{"message":"hello"}\n', encoding="utf-8")

    result = FileLogSource("app", path, declared_format=LogFormat.JSON).fetch()
    assert result.records[0].declared_format is LogFormat.JSON


def test_a_missing_file_is_a_typed_failure_not_an_exception(tmp_path: Path) -> None:
    result = FileLogSource("hostlogs", tmp_path / "absent.log").fetch()

    assert not result.ok
    assert result.failure is not None
    assert result.failure.reason == "unreadable"
    assert result.records == ()


def test_file_source_caps_the_records_it_returns(tmp_path: Path) -> None:
    path = tmp_path / "big.log"
    path.write_text("\n".join(f"line {index}" for index in range(50)), encoding="utf-8")

    result = FileLogSource("hostlogs", path, max_records=10).fetch()
    assert len(result.records) == 10


def test_in_memory_source_serves_its_records() -> None:
    source = InMemoryLogSource("hostlogs", records=[_record()])
    result = source.fetch()

    assert result.ok
    assert len(result.records) == 1
    assert source.kind is LogSourceKind.FILE


def test_in_memory_source_can_simulate_a_failure() -> None:
    source = InMemoryLogSource(
        "siem", failure=LogFetchFailure(source_id="siem", reason="unreachable")
    )
    assert not source.fetch().ok


def test_collect_gathers_from_every_healthy_source() -> None:
    sources = [
        InMemoryLogSource("hostlogs", records=[_record("r1")]),
        InMemoryLogSource("winlogs", records=[_record("r2")]),
    ]
    records, failures = collect(sources)

    assert len(records) == 2
    assert failures == []


def test_one_failing_source_costs_only_that_source() -> None:
    """Partial failure is tolerated: analysis proceeds with what is available."""
    sources = [
        InMemoryLogSource("hostlogs", records=[_record("r1")]),
        InMemoryLogSource("siem", failure=LogFetchFailure(source_id="siem", reason="timeout")),
        InMemoryLogSource("winlogs", records=[_record("r2")]),
    ]
    records, failures = collect(sources)

    assert len(records) == 2
    assert [failure.source_id for failure in failures] == ["siem"]


def test_a_source_that_raises_is_contained() -> None:
    class ExplodingSource(InMemoryLogSource):
        def fetch(self, window: TimeWindow | None = None) -> LogFetchResult:
            raise ConnectionError("connector blew up")

    records, failures = collect(
        [ExplodingSource("bad"), InMemoryLogSource("good", records=[_record()])]
    )

    assert len(records) == 1
    assert failures[0].source_id == "bad"


def test_connectors_expose_no_write_capability() -> None:
    """Log sources pull evidence; none may write or enforce (SAD §7)."""
    for source in (InMemoryLogSource("x"), FileLogSource("y", Path("nowhere"))):
        methods = {name for name in dir(source) if not name.startswith("_")}
        assert not methods & {"write", "delete", "send", "execute", "update"}

"""Behavioral tests for the event stream's loop, driven without a database.

The stream's interesting behavior is all in what it does when *nothing* is
happening: keep the connection alive, notice the client left, refuse to live
forever, and end cleanly when the investigation settles or disappears. Those are
the paths a long-lived connection actually spends its life in, and they are hard
to provoke through HTTP, so the loop is driven directly here with the snapshot
reader stubbed out.
"""

from typing import Any, cast
from uuid import uuid4

import anyio
import pytest

from backend.api import stream as stream_module
from config.settings import Settings

INVESTIGATION_ID = uuid4()


class FakeRequest:
    """A request that reports itself disconnected after N checks."""

    def __init__(self, disconnect_after: int = 1_000) -> None:
        self.checks = 0
        self._after = disconnect_after

    async def is_disconnected(self) -> bool:
        self.checks += 1
        return self.checks >= self._after


def _settings(**overrides: object) -> Settings:
    payload: dict[str, object] = {
        "log_json": False,
        "log_level": "WARNING",
        "stream_poll_seconds": 0.001,
        # Below one poll interval, so a quiet tick is always heartbeat-due.
        "stream_heartbeat_seconds": 0.0001,
        "stream_max_seconds": 10.0,
    }
    payload.update(overrides)
    return Settings(**payload)  # type: ignore[arg-type]


def _drive(request: FakeRequest, settings: Settings) -> list[str]:
    """Run the stream loop to exhaustion from a synchronous test.

    The request and session factory are stand-ins: the loop only ever awaits
    ``is_disconnected`` on the one and hands the other to the (stubbed) reader.
    """
    generator = stream_module.investigation_events(
        cast("Any", request), cast("Any", lambda: None), INVESTIGATION_ID, settings=settings
    )

    async def run() -> list[str]:
        return [frame async for frame in generator]

    return anyio.run(run)


def _stub_reader(monkeypatch: pytest.MonkeyPatch, payloads: list[str | None]) -> None:
    """Replace the snapshot reader with a scripted sequence of states."""
    remaining = list(payloads)

    def read(_factory: object, _investigation_id: object) -> str | None:
        return remaining.pop(0) if remaining else payloads[-1]

    monkeypatch.setattr(stream_module, "read_snapshot", read)


def _snapshot(status: str = "in_progress", revision: int = 1) -> str:
    return f'{{"status":"{status}","event_count":{revision}}}'


def _frames(raw: list[str], kind: str) -> list[str]:
    return [frame for frame in raw if frame.startswith(f"event: {kind}")]


# --- Emitting ---------------------------------------------------------------


def test_each_change_emits_one_snapshot_with_the_next_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_reader(monkeypatch, [_snapshot(revision=1), _snapshot(revision=2), None])

    frames = _drive(FakeRequest(), _settings())
    snapshots = _frames(frames, "snapshot")
    assert len(snapshots) == 2
    assert "id: 1" in snapshots[0]
    assert "id: 2" in snapshots[1]


def test_an_unchanged_state_emits_a_keep_alive_not_a_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Silence must not read as a state change, and must not reap the connection."""
    _stub_reader(monkeypatch, [_snapshot(), _snapshot(), _snapshot(), None])

    frames = _drive(FakeRequest(), _settings())
    assert len(_frames(frames, "snapshot")) == 1
    assert any(frame.startswith(": keep-alive") for frame in frames)


def test_a_quiet_stream_stays_quiet_before_the_heartbeat_is_due(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_reader(monkeypatch, [_snapshot(), _snapshot(), None])

    frames = _drive(FakeRequest(), _settings(stream_heartbeat_seconds=3_600.0))
    assert not [frame for frame in frames if frame.startswith(": keep-alive")]


# --- Ending -----------------------------------------------------------------


def test_a_settled_investigation_ends_the_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """A closed case has nothing further to report."""
    _stub_reader(monkeypatch, [_snapshot("closed")])

    frames = _drive(FakeRequest(), _settings())
    assert len(_frames(frames, "snapshot")) == 1
    assert "investigation closed" in _frames(frames, "end")[0]


def test_an_archived_investigation_ends_the_stream_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_reader(monkeypatch, [_snapshot("archived")])

    frames = _drive(FakeRequest(), _settings())
    assert _frames(frames, "end")


def test_a_case_that_disappears_mid_stream_ends_rather_than_repeating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A soft delete during a long connection must not leave a stale final frame."""
    _stub_reader(monkeypatch, [_snapshot(), None])

    frames = _drive(FakeRequest(), _settings())
    assert "no longer available" in _frames(frames, "end")[0]


def test_a_connection_does_not_live_forever(monkeypatch: pytest.MonkeyPatch) -> None:
    """A connection nobody bounds is one nobody notices leaking."""
    _stub_reader(monkeypatch, [_snapshot()])

    frames = _drive(FakeRequest(), _settings(stream_max_seconds=0.002))
    assert "connection lifetime reached" in _frames(frames, "end")[0]


def test_a_departed_client_stops_the_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """No end frame: there is nobody left to read it."""
    _stub_reader(monkeypatch, [_snapshot()])
    request = FakeRequest(disconnect_after=2)

    frames = _drive(request, _settings())
    assert not _frames(frames, "end")
    assert request.checks == 2


def test_unparseable_state_is_not_treated_as_terminal() -> None:
    """Ending a stream on a payload we could not read would hide the problem."""
    assert stream_module._is_terminal("not json") is False

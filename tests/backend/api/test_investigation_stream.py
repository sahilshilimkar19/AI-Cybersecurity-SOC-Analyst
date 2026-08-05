"""Tests for the live investigation stream.

The property that matters is not "events arrive" — it is that **every event is a
whole snapshot**. That is what makes a dropped connection recoverable without a
replay log: whatever the client missed, the next message it receives is the
complete current truth.

The frame-formatting tests run without a database. The end-to-end subscription
tests need one and are skipped without ``SOC_TEST_DATABASE_URL``.
"""

import json
from typing import Any

from fastapi.testclient import TestClient

from backend.api.stream import format_event
from models.enums import UserRole
from tests.backend.api.test_investigation_api import _run

# --- Frame format -----------------------------------------------------------


def test_a_frame_names_its_event_and_carries_its_data() -> None:
    frame = format_event("snapshot", '{"status":"open"}', event_id=7)

    assert frame.startswith("event: snapshot\n")
    assert "id: 7\n" in frame
    assert 'data: {"status":"open"}' in frame
    assert frame.endswith("\n\n")


def test_an_embedded_newline_cannot_terminate_a_frame_early() -> None:
    """A payload with a newline in it would otherwise truncate the message."""
    frame = format_event("snapshot", "line one\nline two")

    assert frame.count("data: ") == 2
    assert frame.endswith("\n\n")
    # Exactly one blank line, at the end: the frame boundary is where we put it.
    assert frame[:-2].count("\n\n") == 0


def test_an_id_is_optional() -> None:
    assert "id:" not in format_event("end", "{}")


# --- Subscribing ------------------------------------------------------------


def _events(raw: str) -> list[tuple[str, dict[str, Any]]]:
    """Parse an SSE body into (event, data) pairs, ignoring keep-alive comments."""
    parsed: list[tuple[str, dict[str, Any]]] = []
    for block in raw.split("\n\n"):
        lines = [line for line in block.splitlines() if line and not line.startswith(":")]
        if not lines:
            continue
        name = next((line[7:] for line in lines if line.startswith("event: ")), "")
        data = "".join(line[6:] for line in lines if line.startswith("data: "))
        parsed.append((name, json.loads(data) if data else {}))
    return parsed


def test_a_settled_investigation_streams_one_snapshot_then_ends(
    client: TestClient, authenticate: Any
) -> None:
    """A closed case has nothing further to report, so the stream closes too."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)
    client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve"},
        headers=authenticate(UserRole.SENIOR_ANALYST),
    )

    with client.stream(
        "GET", f"/investigations/{created['id']}/stream", headers=headers
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    events = _events(body)
    assert [name for name, _ in events] == ["snapshot", "end"]


def test_every_event_is_a_whole_snapshot(client: TestClient, authenticate: Any) -> None:
    """Not a delta. A client that missed messages needs no replay to catch up."""
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)
    client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve"},
        headers=authenticate(UserRole.SENIOR_ANALYST),
    )

    with client.stream(
        "GET", f"/investigations/{created['id']}/stream", headers=headers
    ) as response:
        body = "".join(response.iter_text())

    name, payload = _events(body)[0]
    assert name == "snapshot"
    assert {"id", "status", "pipeline", "updated_at", "pending_approvals"} <= set(payload)
    assert payload["id"] == created["id"]


def test_the_snapshot_reports_stage_progress(client: TestClient, authenticate: Any) -> None:
    headers = authenticate(UserRole.ANALYST)
    created = _run(client, headers)
    client.post(
        f"/investigations/{created['id']}/decision",
        json={"decision": "approve"},
        headers=authenticate(UserRole.SENIOR_ANALYST),
    )

    with client.stream(
        "GET", f"/investigations/{created['id']}/stream", headers=headers
    ) as response:
        body = "".join(response.iter_text())

    _, payload = _events(body)[0]
    stages = {stage["name"]: stage for stage in payload["pipeline"]}
    assert stages["log_analysis"]["complete"] is True
    assert stages["threat_detection"]["complete"] is True


def test_streaming_an_unknown_investigation_is_a_404_before_any_frame(
    client: TestClient, authenticate: Any
) -> None:
    """Not a 200 carrying an error the client has to parse to notice."""
    missing = "00000000-0000-0000-0000-000000000000"
    response = client.get(
        f"/investigations/{missing}/stream", headers=authenticate(UserRole.ANALYST)
    )
    assert response.status_code == 404


def test_the_stream_requires_a_capability(client: TestClient, authenticate: Any) -> None:
    created = _run(client, authenticate(UserRole.ANALYST))
    assert client.get(f"/investigations/{created['id']}/stream").status_code == 401

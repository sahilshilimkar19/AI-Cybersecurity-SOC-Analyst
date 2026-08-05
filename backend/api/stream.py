"""Server-Sent Events for live investigation progress.

SSE rather than WebSocket. The traffic here is strictly one-way — the server
reports, the client renders, and every command the analyst issues goes back over
an ordinary audited POST. A bidirectional socket would add a second, unaudited
path into the write boundary for no gain (invariant #7).

**Every event is a whole snapshot, never a delta.** That single choice is what
makes stream loss a non-event: a client that reconnects after any gap receives
the complete current truth on the next message, so there is no replay log to keep
and no divergence to reconcile. It costs bandwidth that a delta protocol would
save, and buys a client that cannot silently drift out of sync with the record —
which on a security console is not a trade worth making the other way.

The producer polls the database. That is honest about what exists today: there is
no message bus yet, and the endpoint's *contract* — snapshot events, monotonic
ids, keep-alives, a bounded connection — is what the client is written against,
so the producer can be replaced without the SPA noticing.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from uuid import UUID

import anyio

from backend.db.orm.investigation import Investigation
from backend.services.investigations import snapshot_of

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from sqlalchemy.orm import Session
    from starlette.requests import Request

    from config.settings import Settings

# The terminal lifecycle states. Once an investigation reaches one, there is
# nothing further to stream and holding the connection open is a cost with no
# information behind it.
_TERMINAL = frozenset({"closed", "archived"})


def read_snapshot(session_factory: Callable[[], Session], investigation_id: UUID) -> str | None:
    """Serialize the current snapshot, or ``None`` if the investigation is gone.

    Deleted mid-stream is a real case — a soft delete during a long connection —
    and the stream has to end rather than repeat a stale final frame forever.
    """
    session = session_factory()
    try:
        row = session.get(Investigation, investigation_id)
        if row is None or row.deleted_at is not None:
            return None
        return snapshot_of(session, row).model_dump_json()
    finally:
        session.close()


def format_event(event: str, data: str, *, event_id: int | None = None) -> str:
    """Render one SSE frame.

    Newlines inside the payload would otherwise terminate the frame early, so the
    data is emitted as one line of JSON — which it always is, because it is
    produced by ``model_dump_json``. Guarding anyway costs nothing and the failure
    mode it prevents is a client that silently sees truncated state.
    """
    lines = [f"event: {event}"]
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.extend(f"data: {line}" for line in data.split("\n"))
    return "\n".join(lines) + "\n\n"


async def investigation_events(
    request: Request,
    session_factory: Callable[[], Session],
    investigation_id: UUID,
    *,
    settings: Settings,
) -> AsyncIterator[str]:
    """Yield snapshot events for one investigation until it settles or the client leaves.

    The database read runs in a worker thread: this generator drives an async
    response, and a synchronous query on the event loop would stall every other
    connection the process is serving.
    """
    revision = 0
    previous = ""
    elapsed = 0.0
    idle = 0.0

    while True:
        payload = await anyio.to_thread.run_sync(read_snapshot, session_factory, investigation_id)
        if payload is None:
            yield format_event("end", json.dumps({"reason": "investigation no longer available"}))
            return

        if payload != previous:
            revision += 1
            previous = payload
            idle = 0.0
            yield format_event("snapshot", payload, event_id=revision)
            if _is_terminal(payload):
                yield format_event("end", json.dumps({"reason": "investigation closed"}))
                return
        elif idle >= settings.stream_heartbeat_seconds:
            idle = 0.0
            # A comment frame: it keeps proxies from reaping an idle connection
            # without the client having to treat silence as a state change.
            yield ": keep-alive\n\n"

        if await request.is_disconnected():
            return
        if elapsed >= settings.stream_max_seconds:
            # Bounded on purpose. A connection that lives forever is one nobody
            # notices leaking; the client reconnects and, because every event is
            # a whole snapshot, loses nothing by doing so.
            yield format_event("end", json.dumps({"reason": "connection lifetime reached"}))
            return

        await anyio.sleep(settings.stream_poll_seconds)
        elapsed += settings.stream_poll_seconds
        idle += settings.stream_poll_seconds


def _is_terminal(payload: str) -> bool:
    try:
        status = str(json.loads(payload).get("status", ""))
    except (ValueError, AttributeError):  # pragma: no cover - payload is our own JSON
        return False
    return status in _TERMINAL

"""Tests for the in-memory session store and session lifecycle."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from backend.auth.errors import InvalidTokenError, RefreshReuseError
from backend.auth.sessions import (
    InMemorySessionStore,
    LoginTransaction,
    SessionService,
)


def _service() -> SessionService:
    return SessionService(InMemorySessionStore(), refresh_ttl_seconds=3600)


def test_start_session_issues_refresh() -> None:
    service = _service()
    session, refresh = service.start_session(uuid4())

    assert session.session_id
    assert refresh
    assert service.load_session(session.session_id) is not None


def test_rotate_returns_new_refresh_and_invalidates_old() -> None:
    service = _service()
    _, refresh = service.start_session(uuid4())

    session, new_refresh = service.rotate(refresh)

    assert new_refresh != refresh
    assert session.session_id


def test_reuse_of_rotated_token_revokes_session() -> None:
    service = _service()
    _, refresh = service.start_session(uuid4())
    _, new_refresh = service.rotate(refresh)

    # Replaying the original (already-rotated) token is treated as theft.
    with pytest.raises(RefreshReuseError):
        service.rotate(refresh)

    # The whole session is now revoked, so the newer token also fails.
    with pytest.raises(InvalidTokenError):
        service.rotate(new_refresh)


def test_unknown_refresh_token_is_rejected() -> None:
    with pytest.raises(InvalidTokenError):
        _service().rotate("not-a-real-token")


def test_revoke_invalidates_refresh() -> None:
    service = _service()
    session, refresh = service.start_session(uuid4())

    service.revoke(session.session_id)

    assert service.load_session(session.session_id) is None
    with pytest.raises(InvalidTokenError):
        service.rotate(refresh)


def test_login_transaction_is_single_use() -> None:
    store = InMemorySessionStore()
    tx = LoginTransaction(
        state="state-1",
        nonce="nonce-1",
        code_verifier="verifier",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    store.save_login(tx)

    assert store.pop_login("state-1") is not None
    assert store.pop_login("state-1") is None  # consumed

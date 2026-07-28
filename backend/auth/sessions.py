"""Server-side sessions and rotating refresh tokens.

After OIDC login the platform starts a session and issues an opaque refresh
token. Refresh tokens are single-use and rotated: presenting a rotated token
again is treated as theft and revokes the whole session (reuse detection).

Only a hash of each refresh token is stored; the plaintext is returned to the
client once. Short-lived login transactions (OIDC state/nonce/PKCE verifier) are
also held here so the PKCE verifier never leaves the server.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from pydantic import BaseModel

from backend.auth.errors import InvalidTokenError, RefreshReuseError

if TYPE_CHECKING:
    from redis import Redis


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


class SessionRecord(BaseModel):
    """A server-side session."""

    session_id: str
    user_id: UUID
    created_at: datetime
    expires_at: datetime


class RefreshRecord(BaseModel):
    """A stored refresh token (by hash)."""

    token_hash: str
    session_id: str
    user_id: UUID
    expires_at: datetime
    used: bool = False


class LoginTransaction(BaseModel):
    """Short-lived OIDC login state held between authorize and callback."""

    state: str
    nonce: str
    code_verifier: str
    expires_at: datetime


class SessionStore(Protocol):
    """Persistence interface for sessions, refresh tokens, and login state."""

    def save_session(self, record: SessionRecord) -> None: ...
    def load_session(self, session_id: str) -> SessionRecord | None: ...
    def delete_session(self, session_id: str) -> None: ...
    def save_refresh(self, record: RefreshRecord) -> None: ...
    def load_refresh(self, token_hash: str) -> RefreshRecord | None: ...
    def delete_refreshes_for_session(self, session_id: str) -> None: ...
    def save_login(self, transaction: LoginTransaction) -> None: ...
    def pop_login(self, state: str) -> LoginTransaction | None: ...


class InMemorySessionStore:
    """In-memory store for tests and single-process local development."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}
        self._refresh: dict[str, RefreshRecord] = {}
        self._logins: dict[str, LoginTransaction] = {}

    def save_session(self, record: SessionRecord) -> None:
        self._sessions[record.session_id] = record

    def load_session(self, session_id: str) -> SessionRecord | None:
        return self._sessions.get(session_id)

    def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def save_refresh(self, record: RefreshRecord) -> None:
        self._refresh[record.token_hash] = record

    def load_refresh(self, token_hash: str) -> RefreshRecord | None:
        return self._refresh.get(token_hash)

    def delete_refreshes_for_session(self, session_id: str) -> None:
        for token_hash in [h for h, r in self._refresh.items() if r.session_id == session_id]:
            self._refresh.pop(token_hash, None)

    def save_login(self, transaction: LoginTransaction) -> None:
        self._logins[transaction.state] = transaction

    def pop_login(self, state: str) -> LoginTransaction | None:
        return self._logins.pop(state, None)


class RedisSessionStore:
    """Redis-backed store with TTLs derived from record expiry."""

    def __init__(self, client: Redis, *, namespace: str = "soc") -> None:
        self._redis = client
        self._ns = namespace

    def _ttl(self, expires_at: datetime) -> int:
        return max(1, int((expires_at - _now()).total_seconds()))

    def save_session(self, record: SessionRecord) -> None:
        self._redis.set(
            f"{self._ns}:sess:{record.session_id}",
            record.model_dump_json(),
            ex=self._ttl(record.expires_at),
        )

    def load_session(self, session_id: str) -> SessionRecord | None:
        raw = self._redis.get(f"{self._ns}:sess:{session_id}")
        return SessionRecord.model_validate_json(raw) if raw else None

    def delete_session(self, session_id: str) -> None:
        self._redis.delete(f"{self._ns}:sess:{session_id}")

    def save_refresh(self, record: RefreshRecord) -> None:
        ttl = self._ttl(record.expires_at)
        self._redis.set(f"{self._ns}:refresh:{record.token_hash}", record.model_dump_json(), ex=ttl)
        set_key = f"{self._ns}:sessrefresh:{record.session_id}"
        self._redis.sadd(set_key, record.token_hash)
        self._redis.expire(set_key, ttl)

    def load_refresh(self, token_hash: str) -> RefreshRecord | None:
        raw = self._redis.get(f"{self._ns}:refresh:{token_hash}")
        return RefreshRecord.model_validate_json(raw) if raw else None

    def delete_refreshes_for_session(self, session_id: str) -> None:
        set_key = f"{self._ns}:sessrefresh:{session_id}"
        for token_hash in self._redis.smembers(set_key):
            key = token_hash.decode() if isinstance(token_hash, bytes) else token_hash
            self._redis.delete(f"{self._ns}:refresh:{key}")
        self._redis.delete(set_key)

    def save_login(self, transaction: LoginTransaction) -> None:
        self._redis.set(
            f"{self._ns}:login:{transaction.state}",
            transaction.model_dump_json(),
            ex=self._ttl(transaction.expires_at),
        )

    def pop_login(self, state: str) -> LoginTransaction | None:
        raw = self._redis.getdel(f"{self._ns}:login:{state}")
        return LoginTransaction.model_validate_json(raw) if raw else None


class SessionService:
    """Session lifecycle: start, rotate (with reuse detection), and revoke."""

    def __init__(self, store: SessionStore, *, refresh_ttl_seconds: int) -> None:
        self._store = store
        self._refresh_ttl = refresh_ttl_seconds

    def start_session(self, user_id: UUID) -> tuple[SessionRecord, str]:
        """Create a session and issue its first refresh token (plaintext)."""
        now = _now()
        session = SessionRecord(
            session_id=secrets.token_urlsafe(32),
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(seconds=self._refresh_ttl),
        )
        self._store.save_session(session)
        return session, self._issue_refresh(session)

    def _issue_refresh(self, session: SessionRecord) -> str:
        plaintext = secrets.token_urlsafe(48)
        self._store.save_refresh(
            RefreshRecord(
                token_hash=_hash_token(plaintext),
                session_id=session.session_id,
                user_id=session.user_id,
                expires_at=session.expires_at,
            )
        )
        return plaintext

    def rotate(self, refresh_token: str) -> tuple[SessionRecord, str]:
        """Rotate a refresh token, returning its session and a new refresh token."""
        now = _now()
        record = self._store.load_refresh(_hash_token(refresh_token))
        if record is None or record.expires_at <= now:
            raise InvalidTokenError("invalid refresh token")
        if record.used:
            # Replay of an already-rotated token: revoke the whole session.
            self._store.delete_session(record.session_id)
            self._store.delete_refreshes_for_session(record.session_id)
            raise RefreshReuseError("refresh token reuse detected")
        session = self._store.load_session(record.session_id)
        if session is None or session.expires_at <= now:
            raise InvalidTokenError("session expired")
        record.used = True
        self._store.save_refresh(record)
        return session, self._issue_refresh(session)

    def revoke(self, session_id: str) -> None:
        """Revoke a session and all of its refresh tokens (logout)."""
        self._store.delete_session(session_id)
        self._store.delete_refreshes_for_session(session_id)

    def load_session(self, session_id: str) -> SessionRecord | None:
        return self._store.load_session(session_id)

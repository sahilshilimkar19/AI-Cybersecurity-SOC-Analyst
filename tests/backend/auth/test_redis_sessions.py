"""Integration tests for the Redis session store.

Requires a reachable Redis specified by ``SOC_TEST_REDIS_URL``; skipped otherwise.
In CI the URL points at the Redis service.
"""

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import redis

from backend.auth.errors import InvalidTokenError, RefreshReuseError
from backend.auth.sessions import LoginTransaction, RedisSessionStore, SessionService


@pytest.fixture
def redis_store() -> Iterator[RedisSessionStore]:
    url = os.environ.get("SOC_TEST_REDIS_URL")
    if not url:
        pytest.skip("SOC_TEST_REDIS_URL not set; skipping Redis integration tests")

    client = redis.Redis.from_url(url)
    try:
        client.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"redis not reachable: {exc}")
    client.flushdb()
    yield RedisSessionStore(client, namespace="soctest")
    client.flushdb()


def test_redis_session_rotation_and_reuse(redis_store: RedisSessionStore) -> None:
    service = SessionService(redis_store, refresh_ttl_seconds=3600)
    _, refresh = service.start_session(uuid4())

    _, new_refresh = service.rotate(refresh)
    assert new_refresh != refresh

    with pytest.raises(RefreshReuseError):
        service.rotate(refresh)

    with pytest.raises(InvalidTokenError):
        service.rotate(new_refresh)


def test_redis_login_transaction_single_use(redis_store: RedisSessionStore) -> None:
    transaction = LoginTransaction(
        state="state-1",
        nonce="nonce-1",
        code_verifier="verifier",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    redis_store.save_login(transaction)

    assert redis_store.pop_login("state-1") is not None
    assert redis_store.pop_login("state-1") is None

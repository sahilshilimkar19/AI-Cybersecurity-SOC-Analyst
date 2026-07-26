"""Tests for the object-store abstraction and audit signature (no database)."""

import pytest

from backend.db.object_store import InMemoryObjectStore, ObjectStore
from backend.db.repositories.audit import compute_signature


def test_in_memory_put_get_exists() -> None:
    store = InMemoryObjectStore()

    key = store.put("evidence/2026/log-1", b"raw-bytes")

    assert key == "evidence/2026/log-1"
    assert store.exists(key) is True
    assert store.get(key) == b"raw-bytes"
    assert store.exists("missing") is False


def test_get_missing_key_raises() -> None:
    store = InMemoryObjectStore()

    with pytest.raises(KeyError):
        store.get("nope")


def test_in_memory_store_satisfies_protocol() -> None:
    assert isinstance(InMemoryObjectStore(), ObjectStore)


def test_compute_signature_is_deterministic_and_sensitive() -> None:
    payload = {"id": "a", "action": "investigation.created", "entity_id": None}

    assert compute_signature(payload) == compute_signature(dict(payload))

    changed = {**payload, "action": "investigation.closed"}
    assert compute_signature(payload) != compute_signature(changed)

    # SHA-256 hex digest length.
    assert len(compute_signature(payload)) == 64

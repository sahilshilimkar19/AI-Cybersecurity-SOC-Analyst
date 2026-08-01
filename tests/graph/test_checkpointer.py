"""Tests for the pluggable checkpointer factory."""

from types import SimpleNamespace

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from config.settings import Settings
from graph.checkpointer import CheckpointBackend, build_checkpointer, to_psycopg_dsn
from graph.errors import GraphConfigurationError


def test_memory_backend_returns_in_memory_saver() -> None:
    saver = build_checkpointer(Settings())
    assert isinstance(saver, InMemorySaver)


def test_unsupported_backend_fails_fast() -> None:
    # A misconfigured backend must fail fast rather than run without checkpoints.
    bogus = SimpleNamespace(graph_checkpoint_backend="cassandra")
    with pytest.raises(GraphConfigurationError):
        build_checkpointer(bogus)  # type: ignore[arg-type]


def test_supported_backends() -> None:
    assert [backend.value for backend in CheckpointBackend] == ["memory", "postgres"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("postgresql+psycopg://u:p@h:5432/db", "postgresql://u:p@h:5432/db"),
        ("postgresql://u:p@h:5432/db", "postgresql://u:p@h:5432/db"),
    ],
)
def test_sqlalchemy_url_is_converted_to_psycopg_dsn(url: str, expected: str) -> None:
    assert to_psycopg_dsn(url) == expected

"""Fixtures for graph tests.

The graph runs entirely in-memory (in-memory checkpointer), so these tests need
no database or Redis and run everywhere.
"""

from collections.abc import Iterator

import pytest

from config.settings import Settings
from graph.runtime import InvestigationGraphService, build_graph_runtime


@pytest.fixture
def service() -> InvestigationGraphService:
    """A fresh runtime with an isolated in-memory checkpointer per test."""
    return build_graph_runtime(Settings())


@pytest.fixture
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Freeze the node ``updated_at`` clock for deterministic assertions."""
    stamp = "2026-01-01T00:00:00+00:00"
    monkeypatch.setattr("graph.nodes._utcnow", lambda: stamp)
    yield stamp

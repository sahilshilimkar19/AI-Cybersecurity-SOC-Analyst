"""Integration tests for the durable (PostgreSQL) graph checkpointer.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. This is the test that
proves the point of durable checkpointing: a paused investigation survives the
process that started it (invariant #6).
"""

import os
from collections.abc import Iterator
from uuid import uuid4

import pytest

from config.settings import Settings
from graph.builder import build_investigation_graph
from graph.checkpointer import build_checkpointer
from graph.runtime import InvestigationGraphService
from models.enums import InvestigationStatus


@pytest.fixture
def pg_settings() -> Settings:
    url = os.environ.get("SOC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("SOC_TEST_DATABASE_URL not set; skipping database integration tests")
    return Settings(database_url=url, graph_checkpoint_backend="postgres")


@pytest.fixture
def durable_runtime(pg_settings: Settings) -> Iterator[InvestigationGraphService]:
    """A runtime whose checkpoints live in PostgreSQL."""
    checkpointer = build_checkpointer(pg_settings)
    yield InvestigationGraphService(build_investigation_graph(checkpointer=checkpointer))


def _fresh_runtime(settings: Settings) -> InvestigationGraphService:
    """Simulate a new worker process: new connection, new saver, same database."""
    return InvestigationGraphService(
        build_investigation_graph(checkpointer=build_checkpointer(settings))
    )


def test_checkpoints_are_written_to_postgres(
    durable_runtime: InvestigationGraphService,
) -> None:
    investigation_id = str(uuid4())
    result = durable_runtime.start(investigation_id=investigation_id, trigger_source="analyst")

    assert result.awaiting_human is True
    assert durable_runtime.history(investigation_id)


def test_paused_investigation_survives_a_worker_restart(
    durable_runtime: InvestigationGraphService, pg_settings: Settings
) -> None:
    investigation_id = str(uuid4())
    durable_runtime.start(investigation_id=investigation_id, trigger_source="alert")

    # A different worker picks the investigation up and resumes it.
    restarted = _fresh_runtime(pg_settings)

    pending = restarted.get_state(investigation_id)
    assert pending.awaiting_human is True
    assert pending.status == InvestigationStatus.AWAITING_APPROVAL.value

    resumed = restarted.resume(investigation_id=investigation_id, decision="approve")
    assert resumed.status == InvestigationStatus.CLOSED.value
    assert [t["node"] for t in resumed.node_history] == [
        "ingest_seed",
        "triage",
        "human_gate",
        "close",
    ]


def test_investigations_are_isolated_by_thread(
    durable_runtime: InvestigationGraphService,
) -> None:
    first, second = str(uuid4()), str(uuid4())
    durable_runtime.start(investigation_id=first, trigger_source="analyst")
    durable_runtime.start(investigation_id=second, trigger_source="alert")

    durable_runtime.resume(investigation_id=first, decision="approve")

    assert durable_runtime.get_state(first).status == InvestigationStatus.CLOSED.value
    assert durable_runtime.get_state(second).awaiting_human is True

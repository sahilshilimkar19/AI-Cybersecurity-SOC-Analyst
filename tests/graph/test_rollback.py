"""Tests for checkpoint history and rollback (rollback-by-retain)."""

import pytest

from graph.errors import InvalidResumeError, InvestigationNotFoundError
from graph.runtime import InvestigationGraphService


def test_history_lists_checkpoints_newest_first(service: InvestigationGraphService) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    history = service.history("inv-1")
    assert len(history) >= 2
    # The most recent checkpoint is the paused human gate.
    assert history[0].pending is True
    assert all(ref.checkpoint_id for ref in history)


def test_history_unknown_investigation_raises(service: InvestigationGraphService) -> None:
    with pytest.raises(InvestigationNotFoundError):
        service.history("nope")


def test_rollback_to_prior_checkpoint_reruns_forward(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    service.resume(investigation_id="inv-1", decision="approve")  # closed

    # Find a checkpoint from before the gate decision (one that still has work to do).
    pending_checkpoints = [ref for ref in service.history("inv-1") if ref.pending]
    assert pending_checkpoints, "expected at least one resumable checkpoint"
    target = pending_checkpoints[-1].checkpoint_id

    result = service.rollback(investigation_id="inv-1", checkpoint_id=target)
    # Re-running from a pre-gate checkpoint pauses at the gate again.
    assert result.awaiting_human is True


def test_rollback_to_unknown_checkpoint_fails_fast(
    service: InvestigationGraphService,
) -> None:
    service.start(investigation_id="inv-1", trigger_source="analyst")
    with pytest.raises(InvalidResumeError):
        service.rollback(investigation_id="inv-1", checkpoint_id="deadbeef")

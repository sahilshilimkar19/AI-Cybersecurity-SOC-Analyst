"""Per-node retry policy for the graph.

Transient node failures retry with exponential backoff + jitter, bounded by a
maximum attempt count, and re-run idempotently from the node's checkpoint
(EDS §5 retry policies). Only :class:`~graph.errors.TransientNodeError` is
retried; every other error fails fast so it can be routed to a human gate rather
than silently retried.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langgraph.types import RetryPolicy

from graph.errors import TransientNodeError

if TYPE_CHECKING:
    from config.settings import Settings


def default_retry_policy(settings: Settings) -> RetryPolicy:
    """Build the default per-node retry policy from configuration."""
    return RetryPolicy(
        initial_interval=settings.graph_retry_initial_seconds,
        backoff_factor=settings.graph_retry_backoff_factor,
        max_interval=settings.graph_retry_max_seconds,
        max_attempts=settings.graph_max_retries,
        jitter=True,
        retry_on=(TransientNodeError,),
    )

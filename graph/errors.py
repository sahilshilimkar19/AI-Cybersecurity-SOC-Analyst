"""Errors raised by the orchestration graph.

These surface at the graph's public interface (start/resume/rollback, called by
the backend). ``TransientNodeError`` is special: it is the only failure the
default retry policy retries — every other error fails fast and is routed to a
human gate rather than silently swallowed (EDS §5 error recovery).
"""

from __future__ import annotations


class GraphError(Exception):
    """Base error for the orchestration graph."""


class GraphConfigurationError(GraphError):
    """The graph was assembled or configured with unsupported settings."""


class InvestigationNotFoundError(GraphError):
    """No checkpointed state exists for the requested investigation."""


class InvalidResumeError(GraphError):
    """A resume was attempted with no pending human gate or an invalid decision."""


class TransientNodeError(GraphError):
    """A recoverable node failure (timeout/transient dependency fault).

    This is the only error the default retry policy retries; raising it signals
    that re-running the node from its checkpoint is safe and idempotent.
    """

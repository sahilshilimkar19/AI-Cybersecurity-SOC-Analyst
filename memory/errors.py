"""Errors raised by the memory layer."""

from __future__ import annotations


class MemoryError(Exception):
    """Base error for the memory layer."""


class MemoryConfigurationError(MemoryError):
    """A memory tier was configured with an unsupported backend."""


class MemoryAccessError(MemoryError):
    """A caller attempted an operation its access rules forbid.

    Raised, for example, when something tries to write to knowledge memory, which
    is read-only to agents — the prompt-injection safety boundary (invariant #3).
    """


class CorruptMemoryError(MemoryError):
    """A stored entry failed validation on read and was quarantined."""

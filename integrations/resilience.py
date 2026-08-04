"""Shared resilience primitives for external adapters (EDS §3.12, SAD §7).

Every integration is its own failure domain: a cache, a rate limiter, and a
circuit breaker, so one dependency's outage degrades exactly one capability
(invariant #6). Those three pieces are the same everywhere, so they live here
once rather than being re-invented — subtly differently — per adapter.

Each primitive takes an injectable monotonic clock. That is not a testing
convenience bolted on afterwards: time-dependent behavior that can only be
verified with ``sleep`` is behavior that is verified badly, and expiry, backoff,
and recovery are precisely the paths that must not be left to chance.

* :class:`TtlCache` — bounded, expiring, and able to hand back a **stale** entry
  on request, which is what lets a caller degrade to a known-old answer instead
  of to nothing.
* :class:`RateLimiter` — a token bucket, so a burst is allowed but a sustained
  rate is not. Free intel tiers are strict, and being throttled by a provider is
  a worse outcome than pacing ourselves.
* :class:`CircuitBreaker` — stops hammering a service that is already failing,
  and probes for recovery with a single request rather than a stampede.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Generic, TypeVar

from config.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

_logger = get_logger(__name__)

T = TypeVar("T")


@dataclass
class _CacheEntry(Generic[T]):
    value: T
    expires_at: float


class TtlCache(Generic[T]):
    """A bounded cache whose entries expire, and can still be read when stale."""

    def __init__(
        self,
        *,
        ttl_seconds: float,
        max_entries: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, _CacheEntry[T]] = OrderedDict()

    def get(self, key: str) -> T | None:
        """Return a live value, or ``None`` if absent or expired."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() >= entry.expires_at:
            return None
        self._entries.move_to_end(key)
        return entry.value

    def get_stale(self, key: str) -> T | None:
        """Return a value even if it has expired.

        Serving a known-old answer and saying so beats serving nothing, provided
        the caller marks the result degraded — which is the contract here.
        """
        entry = self._entries.get(key)
        return entry.value if entry is not None else None

    def set(self, key: str, value: T) -> None:
        """Store a value, evicting the least-recently-used entry when full."""
        if self._ttl <= 0:
            return
        self._entries[key] = _CacheEntry(value=value, expires_at=self._clock() + self._ttl)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        """Drop everything."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


class RateLimiter:
    """Token bucket: bursts up to ``capacity``, sustained at ``per_second``."""

    def __init__(
        self,
        *,
        capacity: int,
        per_second: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1:
            raise ValueError("rate limiter capacity must be at least 1")
        self._capacity = float(capacity)
        self._per_second = per_second
        self._clock = clock
        self._tokens = float(capacity)
        self._updated_at = clock()

    @property
    def available(self) -> float:
        """Tokens currently available, after refill."""
        self._refill()
        return self._tokens

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Take tokens if available; report refusal rather than blocking."""
        self._refill()
        if self._tokens < tokens:
            return False
        self._tokens -= tokens
        return True

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated_at)
        self._updated_at = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._per_second)


class BreakerState(StrEnum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Trips after repeated failures; probes once before closing again."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        reset_seconds: float = 60.0,
        name: str = "integration",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure threshold must be at least 1")
        self._failure_threshold = failure_threshold
        self._reset_seconds = reset_seconds
        self._name = name
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._half_open = False

    @property
    def state(self) -> BreakerState:
        """The breaker's state, accounting for elapsed recovery time."""
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock() - self._opened_at >= self._reset_seconds:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    def allow(self) -> bool:
        """Whether a call may proceed.

        In the half-open state exactly one probe is allowed through; further
        calls are refused until it resolves, so recovery is tested with a single
        request rather than with the backlog.
        """
        state = self.state
        if state is BreakerState.CLOSED:
            return True
        if state is BreakerState.OPEN:
            return False
        if self._half_open:
            return False
        self._half_open = True
        return True

    def record_success(self) -> None:
        """Reset the breaker: the dependency is healthy."""
        if self._opened_at is not None:
            _logger.info("circuit_breaker_closed", integration=self._name)
        self._failures = 0
        self._opened_at = None
        self._half_open = False

    def record_failure(self) -> None:
        """Count a failure, tripping the breaker once the threshold is reached."""
        if self._half_open:
            # The probe failed: stay open and restart the recovery clock.
            self._opened_at = self._clock()
            self._half_open = False
            _logger.warning("circuit_breaker_reopened", integration=self._name)
            return

        self._failures += 1
        if self._failures >= self._failure_threshold and self._opened_at is None:
            self._opened_at = self._clock()
            _logger.warning(
                "circuit_breaker_opened", integration=self._name, failures=self._failures
            )

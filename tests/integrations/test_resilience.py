"""Tests for the shared integration resilience primitives.

Every test drives time through an injected clock rather than sleeping: expiry,
refill, and breaker recovery are exactly the paths that must not be verified by
guessing how long a test takes to run.
"""

import pytest

from integrations.resilience import BreakerState, CircuitBreaker, RateLimiter, TtlCache


class FakeClock:
    """A monotonic clock the test advances explicitly."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- TtlCache ---------------------------------------------------------------


def test_cache_returns_a_live_value() -> None:
    cache: TtlCache[str] = TtlCache(ttl_seconds=10, clock=FakeClock())
    cache.set("k", "v")
    assert cache.get("k") == "v"


def test_cache_misses_are_none_not_errors() -> None:
    cache: TtlCache[str] = TtlCache(ttl_seconds=10)
    assert cache.get("absent") is None
    assert cache.get_stale("absent") is None


def test_an_expired_entry_is_not_served_as_live() -> None:
    clock = FakeClock()
    cache: TtlCache[str] = TtlCache(ttl_seconds=10, clock=clock)
    cache.set("k", "v")
    clock.advance(11)
    assert cache.get("k") is None


def test_an_expired_entry_is_still_available_as_stale() -> None:
    """Serving a known-old answer beats serving nothing, provided it is flagged."""
    clock = FakeClock()
    cache: TtlCache[str] = TtlCache(ttl_seconds=10, clock=clock)
    cache.set("k", "v")
    clock.advance(3600)
    assert cache.get_stale("k") == "v"


def test_the_cache_is_bounded_and_evicts_least_recently_used() -> None:
    cache: TtlCache[str] = TtlCache(ttl_seconds=100, max_entries=2)
    cache.set("a", "1")
    cache.set("b", "2")
    cache.get("a")  # refresh 'a'
    cache.set("c", "3")

    assert len(cache) == 2
    assert cache.get_stale("b") is None
    assert cache.get("a") == "1"


def test_a_zero_ttl_disables_caching() -> None:
    cache: TtlCache[str] = TtlCache(ttl_seconds=0)
    cache.set("k", "v")
    assert cache.get("k") is None
    assert len(cache) == 0


def test_clear_drops_everything() -> None:
    cache: TtlCache[str] = TtlCache(ttl_seconds=100)
    cache.set("k", "v")
    cache.clear()
    assert len(cache) == 0


# --- RateLimiter ------------------------------------------------------------


def test_a_burst_up_to_capacity_is_allowed() -> None:
    limiter = RateLimiter(capacity=3, per_second=1.0, clock=FakeClock())
    assert [limiter.try_acquire() for _ in range(3)] == [True, True, True]


def test_the_bucket_refuses_rather_than_blocking() -> None:
    limiter = RateLimiter(capacity=1, per_second=1.0, clock=FakeClock())
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False


def test_tokens_refill_over_time() -> None:
    clock = FakeClock()
    limiter = RateLimiter(capacity=2, per_second=1.0, clock=clock)
    limiter.try_acquire()
    limiter.try_acquire()
    assert limiter.try_acquire() is False

    clock.advance(1.0)
    assert limiter.try_acquire() is True


def test_refill_never_exceeds_capacity() -> None:
    clock = FakeClock()
    limiter = RateLimiter(capacity=2, per_second=1.0, clock=clock)
    clock.advance(1000)
    assert limiter.available == pytest.approx(2.0)


def test_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError, match="capacity"):
        RateLimiter(capacity=0, per_second=1.0)


# --- CircuitBreaker ---------------------------------------------------------


def test_a_healthy_breaker_stays_closed() -> None:
    breaker = CircuitBreaker(failure_threshold=2, clock=FakeClock())
    breaker.record_success()
    assert breaker.state is BreakerState.CLOSED
    assert breaker.allow() is True


def test_the_breaker_trips_at_the_threshold() -> None:
    breaker = CircuitBreaker(failure_threshold=2, clock=FakeClock())
    breaker.record_failure()
    assert breaker.state is BreakerState.CLOSED

    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
    assert breaker.allow() is False


def test_a_success_resets_the_failure_count() -> None:
    breaker = CircuitBreaker(failure_threshold=2, clock=FakeClock())
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    assert breaker.state is BreakerState.CLOSED


def test_the_breaker_half_opens_after_the_reset_interval() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=30, clock=clock)
    breaker.record_failure()
    assert breaker.allow() is False

    clock.advance(30)
    assert breaker.state is BreakerState.HALF_OPEN


def test_recovery_is_probed_with_exactly_one_request() -> None:
    """A stampede against a recovering service is how an outage gets extended."""
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=30, clock=clock)
    breaker.record_failure()
    clock.advance(30)

    assert breaker.allow() is True
    assert breaker.allow() is False


def test_a_successful_probe_closes_the_breaker() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=30, clock=clock)
    breaker.record_failure()
    clock.advance(30)
    breaker.allow()
    breaker.record_success()

    assert breaker.state is BreakerState.CLOSED
    assert breaker.allow() is True


def test_a_failed_probe_reopens_and_restarts_the_clock() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=30, clock=clock)
    breaker.record_failure()
    clock.advance(30)
    breaker.allow()
    breaker.record_failure()

    assert breaker.state is BreakerState.OPEN
    clock.advance(29)
    assert breaker.state is BreakerState.OPEN
    clock.advance(1)
    assert breaker.state is BreakerState.HALF_OPEN


def test_the_threshold_must_be_positive() -> None:
    with pytest.raises(ValueError, match="threshold"):
        CircuitBreaker(failure_threshold=0)

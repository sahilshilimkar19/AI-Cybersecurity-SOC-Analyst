"""Threat-intelligence enrichment adapters (SAD §2.2, §7; EDS §3.12).

Reputation is the one thing in an assessment that the platform cannot derive from
the evidence in front of it — it is an assertion someone else makes about an
indicator. That makes this module a trust boundary, and it is built around a
single rule:

    **An indicator's reputation is only ever set together with the source that
    asserted it.** There is no code path that produces a reputation without a
    source, so "we could not check" can never be rendered as "it looks clean".

Everything else follows from that. The default provider is
:class:`UnavailableReputationProvider`, which reports itself unavailable and fails
every lookup with a reason — an unconfigured deployment therefore produces an
assessment explicitly flagged ``UNAVAILABLE`` with lowered confidence, rather than
one that silently assumes the best.

The VirusTotal adapter is read-only (``GET`` only, no submission), wrapped in the
shared cache / rate limiter / circuit breaker so a slow or throttled provider
degrades this one capability and nothing else (invariant #6). Indicators the
detector marked estate-internal are never submitted: enrichment must not leak the
internal topology to a third party.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

import httpx

from config.logging import get_logger
from integrations.resilience import BreakerState, CircuitBreaker, RateLimiter, TtlCache
from models.enums import EnrichmentStatus
from models.threat import IocReputation, IocType
from tools.iocs import ENRICHABLE_TYPES

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from config.settings import Settings
    from models.threat import IocIndicator

_logger = get_logger(__name__)

# VirusTotal's analysis verdicts are engine votes, not truth. A single engine
# flagging something is routinely a false positive, so a malicious call requires
# corroboration across engines — the same corroboration principle the detection
# rules use, applied to someone else's detections.
_MALICIOUS_ENGINES = 3
_SUSPICIOUS_ENGINES = 1


@dataclass(frozen=True)
class ReputationVerdict:
    """What an intel source said about one indicator."""

    value: str
    reputation: IocReputation
    source: str
    detail: str = ""
    checked_at: datetime | None = None
    # True when served from cache after the live lookup path was unavailable.
    stale: bool = False


@dataclass(frozen=True)
class ReputationFailure:
    """A lookup that did not happen, and why."""

    value: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class ReputationResult:
    """Either a verdict or a typed failure — never both, never neither."""

    verdict: ReputationVerdict | None = None
    failure: ReputationFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None and self.verdict is not None

    @classmethod
    def succeed(cls, verdict: ReputationVerdict) -> ReputationResult:
        return cls(verdict=verdict)

    @classmethod
    def fail(cls, value: str, reason: str, detail: str = "") -> ReputationResult:
        return cls(failure=ReputationFailure(value=value, reason=reason, detail=detail))


class ReputationProvider(Protocol):
    """Read-only reputation lookup for a single indicator."""

    @property
    def name(self) -> str: ...
    @property
    def is_available(self) -> bool: ...
    def lookup(self, ioc: IocIndicator) -> ReputationResult: ...


class UnavailableReputationProvider:
    """The default: no intel source configured.

    Deliberately not a silent no-op. Every lookup fails with a named reason so
    the assessment records *why* it has no reputation data, and the caller marks
    itself degraded instead of proceeding as though the indicators were clean.
    """

    @property
    def name(self) -> str:
        return "none"

    @property
    def is_available(self) -> bool:
        return False

    def lookup(self, ioc: IocIndicator) -> ReputationResult:
        return ReputationResult.fail(
            ioc.value, "not_configured", "no threat-intelligence provider is configured"
        )


class InMemoryReputationProvider:
    """Fixture-driven provider for tests and offline runs."""

    def __init__(
        self,
        reputations: Mapping[str, IocReputation] | None = None,
        *,
        failures: Mapping[str, str] | None = None,
        name: str = "in-memory-intel",
        available: bool = True,
    ) -> None:
        self._reputations = {key.lower(): value for key, value in (reputations or {}).items()}
        self._failures = {key.lower(): value for key, value in (failures or {}).items()}
        self._name = name
        self._available = available

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_available(self) -> bool:
        return self._available

    def lookup(self, ioc: IocIndicator) -> ReputationResult:
        key = ioc.value.lower()
        if key in self._failures:
            return ReputationResult.fail(ioc.value, self._failures[key])
        return ReputationResult.succeed(
            ReputationVerdict(
                value=ioc.value,
                reputation=self._reputations.get(key, IocReputation.UNKNOWN),
                source=self._name,
                detail="fixture reputation",
                checked_at=datetime.now(UTC),
            )
        )


class VirusTotalReputationProvider:
    """VirusTotal v3 adapter — read-only, cached, rate-limited, breaker-guarded."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://www.virustotal.com/api/v3",
        timeout_seconds: float = 5.0,
        client: httpx.Client | None = None,
        cache: TtlCache[ReputationVerdict] | None = None,
        limiter: RateLimiter | None = None,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._client = client
        self._cache = cache if cache is not None else TtlCache[ReputationVerdict](ttl_seconds=3600)
        self._limiter = limiter or RateLimiter(capacity=4, per_second=4 / 60)
        self._breaker = breaker or CircuitBreaker(name="virustotal")

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def is_available(self) -> bool:
        """Configured and not currently tripped.

        Reads the breaker's state rather than calling ``allow()`` — asking
        whether a provider is usable must not consume the half-open probe that
        an actual lookup is entitled to.
        """
        return bool(self._api_key) and self._breaker.state is not BreakerState.OPEN

    def lookup(self, ioc: IocIndicator) -> ReputationResult:
        """Look one indicator up, degrading to cache rather than to a guess."""
        if not self._api_key:
            return ReputationResult.fail(ioc.value, "not_configured", "no VirusTotal API key")

        path = self._path_for(ioc)
        if path is None:
            return ReputationResult.fail(
                ioc.value, "unsupported", f"{ioc.type.value} is not looked up by VirusTotal"
            )

        cache_key = f"{ioc.type.value}:{ioc.value.lower()}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return ReputationResult.succeed(cached)

        if not self._breaker.allow():
            return self._degrade(ioc, cache_key, "circuit_open", "VirusTotal circuit is open")
        if not self._limiter.try_acquire():
            return self._degrade(
                ioc, cache_key, "rate_limited", "local VirusTotal rate limit reached"
            )

        try:
            response = self._get(path)
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            _logger.warning("virustotal_unreachable", indicator_type=ioc.type.value)
            return self._degrade(ioc, cache_key, "unreachable", str(exc))

        if response.status_code == httpx.codes.NOT_FOUND:
            # A genuine answer: VirusTotal has no record. Not a failure, and not
            # evidence of innocence either — it stays UNKNOWN.
            self._breaker.record_success()
            verdict = ReputationVerdict(
                value=ioc.value,
                reputation=IocReputation.UNKNOWN,
                source=self.name,
                detail="no record in VirusTotal",
                checked_at=datetime.now(UTC),
            )
            self._cache.set(cache_key, verdict)
            return ReputationResult.succeed(verdict)

        if response.status_code != httpx.codes.OK:
            self._breaker.record_failure()
            return self._degrade(
                ioc, cache_key, "http_error", f"VirusTotal returned {response.status_code}"
            )

        try:
            stats = _analysis_stats(response.json())
        except (ValueError, KeyError, TypeError) as exc:
            self._breaker.record_failure()
            return self._degrade(ioc, cache_key, "malformed_response", str(exc))

        self._breaker.record_success()
        verdict = ReputationVerdict(
            value=ioc.value,
            reputation=classify_analysis_stats(stats),
            source=self.name,
            detail=(
                f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious "
                f"of {sum(stats.values())} engines"
            ),
            checked_at=datetime.now(UTC),
        )
        self._cache.set(cache_key, verdict)
        return ReputationResult.succeed(verdict)

    # --- Internals --------------------------------------------------------

    def _get(self, path: str) -> httpx.Response:
        headers = {"x-apikey": self._api_key, "accept": "application/json"}
        url = f"{self._base_url}{path}"
        if self._client is not None:
            return self._client.get(url, headers=headers, timeout=self._timeout)
        with httpx.Client(timeout=self._timeout) as client:
            return client.get(url, headers=headers)

    def _degrade(
        self, ioc: IocIndicator, cache_key: str, reason: str, detail: str
    ) -> ReputationResult:
        """Fall back to a stale cached verdict, flagged as such, or fail cleanly."""
        stale = self._cache.get_stale(cache_key)
        if stale is not None:
            return ReputationResult.succeed(
                ReputationVerdict(
                    value=stale.value,
                    reputation=stale.reputation,
                    source=stale.source,
                    detail=f"{stale.detail} (stale: {detail})",
                    checked_at=stale.checked_at,
                    stale=True,
                )
            )
        return ReputationResult.fail(ioc.value, reason, detail)

    @staticmethod
    def _path_for(ioc: IocIndicator) -> str | None:
        """The v3 resource path for an indicator, or ``None`` if unsupported."""
        if ioc.type is IocType.IP_ADDRESS:
            return f"/ip_addresses/{ioc.value}"
        if ioc.type is IocType.DOMAIN:
            return f"/domains/{ioc.value}"
        if ioc.type is IocType.FILE_HASH:
            return f"/files/{ioc.value}"
        if ioc.type is IocType.URL:
            return f"/urls/{url_identifier(ioc.value)}"
        return None


def url_identifier(url: str) -> str:
    """VirusTotal's URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def classify_analysis_stats(stats: Mapping[str, int]) -> IocReputation:
    """Turn engine vote counts into a reputation, requiring corroboration."""
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))

    if malicious >= _MALICIOUS_ENGINES:
        return IocReputation.MALICIOUS
    if malicious >= _SUSPICIOUS_ENGINES or suspicious >= _MALICIOUS_ENGINES:
        return IocReputation.SUSPICIOUS
    if harmless > 0:
        return IocReputation.HARMLESS
    return IocReputation.UNKNOWN


def _analysis_stats(payload: Any) -> dict[str, int]:
    """Pull the engine vote counts out of a v3 response, validating as untrusted."""
    attributes = payload["data"]["attributes"]
    stats = attributes.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        raise TypeError("last_analysis_stats is not an object")
    return {str(key): int(value) for key, value in stats.items() if isinstance(value, int)}


def enrich_indicators(
    iocs: Sequence[IocIndicator],
    provider: ReputationProvider,
    *,
    limit: int = 25,
) -> tuple[list[IocIndicator], EnrichmentStatus, list[str]]:
    """Attach reputations to the eligible indicators.

    Returns the indicators (enriched where possible), the resulting enrichment
    status, and the notes explaining any shortfall. Indicators that were not
    looked up — internal, ineligible, over the budget, or failed — come back
    exactly as they went in: ``UNKNOWN`` and ``enriched=False``.
    """
    notes: list[str] = []
    if not provider.is_available:
        return (
            list(iocs),
            EnrichmentStatus.UNAVAILABLE,
            [f"threat-intelligence provider {provider.name!r} is unavailable"],
        )

    eligible = [
        index for index, ioc in enumerate(iocs) if ioc.type in ENRICHABLE_TYPES and not ioc.internal
    ]
    if not eligible:
        return list(iocs), EnrichmentStatus.COMPLETE, []

    budgeted, deferred = eligible[:limit], eligible[limit:]
    if deferred:
        notes.append(
            f"{len(deferred)} indicator(s) exceeded the enrichment budget of {limit} and "
            "were not looked up"
        )

    enriched = list(iocs)
    succeeded = 0
    for index in budgeted:
        result = provider.lookup(enriched[index])
        if not result.ok or result.verdict is None:
            failure = result.failure
            notes.append(
                f"lookup failed for {enriched[index].defanged}: "
                f"{failure.reason if failure else 'unknown'}"
            )
            continue

        verdict = result.verdict
        succeeded += 1
        enriched[index] = enriched[index].model_copy(
            update={
                "reputation": verdict.reputation,
                "reputation_source": verdict.source,
                "reputation_detail": verdict.detail,
                "enriched": True,
            }
        )
        if verdict.stale:
            notes.append(f"{enriched[index].defanged} served from stale cache")

    if succeeded == 0:
        return enriched, EnrichmentStatus.UNAVAILABLE, notes
    if succeeded < len(budgeted) or deferred or any("stale" in note for note in notes):
        return enriched, EnrichmentStatus.DEGRADED, notes
    return enriched, EnrichmentStatus.COMPLETE, notes


def build_reputation_provider(
    settings: Settings, *, client: httpx.Client | None = None
) -> ReputationProvider:
    """Compose the configured provider, defaulting to none.

    An unset API key yields the unavailable provider rather than a half-working
    one: a deployment that has not configured intel should say so loudly in every
    assessment it produces.
    """
    if settings.threat_intel_provider != "virustotal":
        return UnavailableReputationProvider()

    api_key = settings.virustotal_api_key.get_secret_value()
    if not api_key:
        _logger.warning("virustotal_api_key_missing")
        return UnavailableReputationProvider()

    return VirusTotalReputationProvider(
        api_key=api_key,
        base_url=settings.virustotal_base_url,
        timeout_seconds=settings.threat_intel_timeout_seconds,
        client=client,
        cache=TtlCache[ReputationVerdict](ttl_seconds=settings.threat_intel_cache_ttl_seconds),
        limiter=RateLimiter(
            capacity=settings.threat_intel_rate_limit_per_minute,
            per_second=settings.threat_intel_rate_limit_per_minute / 60.0,
        ),
        breaker=CircuitBreaker(
            failure_threshold=settings.threat_intel_breaker_failure_threshold,
            reset_seconds=settings.threat_intel_breaker_reset_seconds,
            name="virustotal",
        ),
    )

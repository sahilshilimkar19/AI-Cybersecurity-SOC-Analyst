"""Security advisory lookup — fixed versions (SAD §2.5, §7; EDS §3.12).

The single most useful fact a remediation plan can carry is *which version to
move to*. NVD says a range is vulnerable; an advisory says where it stops being
vulnerable. This adapter fetches that, so a recommendation can read "upgrade
log4j-core to 2.17.1" rather than "patch Log4j".

Read-only, wrapped in the shared cache / rate limiter / circuit breaker, and
returning typed failures rather than raising — an advisory outage costs the
*specificity* of a recommendation, never the recommendation itself. Without a
fixed version the guidance falls back to citing the advisory, which is honest
about what is known; a fabricated version number would be worse than no advice
at all, because someone would deploy it.

The default source is :class:`UnavailableAdvisorySource`. GitHub's advisory API
is reachable unauthenticated, but whether this platform makes outbound calls is
an operator's decision, not a default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

import httpx

from config.logging import get_logger
from integrations.resilience import BreakerState, CircuitBreaker, RateLimiter, TtlCache
from models.enums import SourceTrustTier
from models.values import Citation

if TYPE_CHECKING:
    from collections.abc import Sequence

    from config.settings import Settings

_logger = get_logger(__name__)

# GitHub's unauthenticated limit is 60 requests per hour; a token raises it.
_DEFAULT_REQUESTS_PER_WINDOW = 60
_DEFAULT_WINDOW_SECONDS = 3600.0


@dataclass(frozen=True)
class AdvisoryFix:
    """One package's remediation: what is vulnerable, and where it is fixed."""

    package: str
    ecosystem: str | None = None
    vulnerable_range: str | None = None
    fixed_version: str | None = None


@dataclass(frozen=True)
class Advisory:
    """A published security advisory for one CVE."""

    advisory_id: str
    cve_id: str | None = None
    summary: str = ""
    severity: str | None = None
    url: str | None = None
    published_at: datetime | None = None
    fixes: tuple[AdvisoryFix, ...] = ()
    source: str = "github"

    def citation(self) -> Citation:
        """A resolvable reference for the advisory."""
        return Citation(
            source_id="vendor_advisories",
            source="GitHub Security Advisories",
            url=self.url,
            title=self.advisory_id,
            trust_tier=SourceTrustTier.VENDOR,
            published_at=self.published_at,
        )

    def fix_for(self, product: str | None) -> AdvisoryFix | None:
        """The fix whose package best matches a product name.

        Ranked rather than first-match: an advisory routinely lists several
        packages from one family with *different* patched releases, and
        ``log4j-api`` matches ``log4j-core`` well enough to be picked first while
        carrying the wrong version. Attaching the wrong fixed version to a finding
        is worse than attaching none, because it looks authoritative.

        Falls back to the first fix that names any version, because an advisory
        listing one patched release for a family is usually right about the
        family — and a caller with no product name still deserves an answer.
        """
        from tools.versions import product_match_score

        candidates = [fix for fix in self.fixes if fix.fixed_version]
        if not candidates:
            return None
        if product:
            best = max(candidates, key=lambda fix: product_match_score(product, fix.package))
            if product_match_score(product, best.package) > 0:
                return best
        return candidates[0]


@dataclass(frozen=True)
class AdvisoryLookupFailure:
    """A lookup that did not happen, and why."""

    cve_id: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class AdvisoryLookupResult:
    """Either advisories or a typed failure — never both, never neither."""

    advisories: tuple[Advisory, ...] = ()
    failure: AdvisoryLookupFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None

    @classmethod
    def succeed(cls, advisories: Sequence[Advisory]) -> AdvisoryLookupResult:
        return cls(advisories=tuple(advisories))

    @classmethod
    def fail(cls, cve_id: str, reason: str, detail: str = "") -> AdvisoryLookupResult:
        return cls(failure=AdvisoryLookupFailure(cve_id=cve_id, reason=reason, detail=detail))


class AdvisorySource(Protocol):
    """Read-only access to published security advisories."""

    @property
    def name(self) -> str: ...
    @property
    def is_available(self) -> bool: ...
    def fetch(self, cve_id: str) -> AdvisoryLookupResult: ...


class UnavailableAdvisorySource:
    """The default: no advisory feed configured.

    Fails every lookup with a named reason, so a plan built without fixed
    versions records *why* its guidance is less specific than it could be.
    """

    @property
    def name(self) -> str:
        return "none"

    @property
    def is_available(self) -> bool:
        return False

    def fetch(self, cve_id: str) -> AdvisoryLookupResult:
        return AdvisoryLookupResult.fail(
            cve_id, "not_configured", "no advisory source is configured"
        )


@dataclass
class InMemoryAdvisorySource:
    """Fixture-driven source for tests and offline runs."""

    advisories: list[Advisory] = field(default_factory=list)
    failures: frozenset[str] = frozenset()
    name_value: str = "in-memory-advisories"
    available: bool = True

    @property
    def name(self) -> str:
        return self.name_value

    @property
    def is_available(self) -> bool:
        return self.available

    def fetch(self, cve_id: str) -> AdvisoryLookupResult:
        if cve_id.upper() in {item.upper() for item in self.failures}:
            return AdvisoryLookupResult.fail(cve_id, "unreachable")
        matched = [
            item
            for item in self.advisories
            if item.cve_id and item.cve_id.upper() == cve_id.upper()
        ]
        return AdvisoryLookupResult.succeed(matched)


class GitHubAdvisorySource:
    """GitHub Security Advisories adapter — read-only and breaker-guarded."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.github.com/advisories",
        token: str = "",
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
        cache: TtlCache[tuple[Advisory, ...]] | None = None,
        limiter: RateLimiter | None = None,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout_seconds
        self._client = client
        self._cache = (
            cache if cache is not None else TtlCache[tuple[Advisory, ...]](ttl_seconds=21_600)
        )
        self._limiter = limiter or RateLimiter(
            capacity=_DEFAULT_REQUESTS_PER_WINDOW,
            per_second=_DEFAULT_REQUESTS_PER_WINDOW / _DEFAULT_WINDOW_SECONDS,
        )
        self._breaker = breaker or CircuitBreaker(name="github_advisories")

    @property
    def name(self) -> str:
        return "github_advisories"

    @property
    def is_available(self) -> bool:
        """Reads the breaker's state so asking does not consume the recovery probe."""
        return self._breaker.state is not BreakerState.OPEN

    def fetch(self, cve_id: str) -> AdvisoryLookupResult:
        """Fetch the advisories published for one CVE."""
        cache_key = cve_id.upper()
        cached = self._cache.get(cache_key)
        if cached is not None:
            return AdvisoryLookupResult.succeed(cached)

        if not self._breaker.allow():
            return self._degrade(cache_key, cve_id, "circuit_open", "the advisory circuit is open")
        if not self._limiter.try_acquire():
            return self._degrade(
                cache_key, cve_id, "rate_limited", "local advisory rate limit reached"
            )

        try:
            response = self._get({"cve_id": cve_id})
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            _logger.warning("advisory_source_unreachable", cve_id=cve_id)
            return self._degrade(cache_key, cve_id, "unreachable", str(exc))

        if response.status_code != httpx.codes.OK:
            self._breaker.record_failure()
            return self._degrade(
                cache_key, cve_id, "http_error", f"advisory source returned {response.status_code}"
            )

        try:
            advisories = tuple(parse_github_advisories(response.json()))
        except (ValueError, KeyError, TypeError) as exc:
            self._breaker.record_failure()
            return self._degrade(cache_key, cve_id, "malformed_response", str(exc))

        self._breaker.record_success()
        self._cache.set(cache_key, advisories)
        return AdvisoryLookupResult.succeed(advisories)

    # --- Internals --------------------------------------------------------

    def _get(self, params: dict[str, str]) -> httpx.Response:
        headers = {"accept": "application/vnd.github+json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        if self._client is not None:
            return self._client.get(
                self._base_url, params=params, headers=headers, timeout=self._timeout
            )
        with httpx.Client(timeout=self._timeout) as client:
            return client.get(self._base_url, params=params, headers=headers)

    def _degrade(
        self, cache_key: str, cve_id: str, reason: str, detail: str
    ) -> AdvisoryLookupResult:
        """Serve an expired cached answer, or fail cleanly.

        An advisory's fixed version does not change once published, so a stale
        copy is materially as good as a fresh one — unlike a reputation, which is
        a live judgement. It is served without a staleness flag for that reason.
        """
        stale = self._cache.get_stale(cache_key)
        if stale is not None:
            return AdvisoryLookupResult.succeed(stale)
        return AdvisoryLookupResult.fail(cve_id, reason, detail)


def parse_github_advisories(payload: Any) -> list[Advisory]:
    """Parse a GitHub advisories response, validating it as untrusted input."""
    if not isinstance(payload, list):
        raise TypeError("advisory response is not a list")

    advisories: list[Advisory] = []
    for item in payload:
        if not isinstance(item, dict) or not item.get("ghsa_id"):
            continue
        advisories.append(
            Advisory(
                advisory_id=str(item["ghsa_id"]),
                cve_id=_optional(item.get("cve_id")),
                summary=str(item.get("summary", "")).strip(),
                severity=_optional(item.get("severity")),
                url=_optional(item.get("html_url")),
                published_at=_parse_timestamp(item.get("published_at")),
                fixes=tuple(_parse_fixes(item.get("vulnerabilities"))),
            )
        )
    return advisories


def _parse_fixes(vulnerabilities: Any) -> list[AdvisoryFix]:
    if not isinstance(vulnerabilities, list):
        return []

    fixes: list[AdvisoryFix] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        name = str(package.get("name", "")).strip() if isinstance(package, dict) else ""
        if not name:
            continue
        fixes.append(
            AdvisoryFix(
                package=name,
                ecosystem=(
                    _optional(package.get("ecosystem")) if isinstance(package, dict) else None
                ),
                vulnerable_range=_optional(entry.get("vulnerable_version_range")),
                fixed_version=_parse_fixed_version(entry.get("first_patched_version")),
            )
        )
    return fixes


def _parse_fixed_version(value: Any) -> str | None:
    """Read the patched version, which the API spells two different ways.

    The REST endpoint returns a bare string; the GraphQL shape returns an object
    with an ``identifier``. Accepting both means a change of transport does not
    silently drop the single most useful field in the response.
    """
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        return _optional(value.get("identifier"))
    return None


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _optional(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def build_advisory_source(
    settings: Settings, *, client: httpx.Client | None = None
) -> AdvisorySource:
    """Compose the configured advisory source, defaulting to none."""
    if settings.advisory_source != "github":
        return UnavailableAdvisorySource()

    return GitHubAdvisorySource(
        base_url=settings.github_advisories_url,
        token=settings.github_token.get_secret_value(),
        timeout_seconds=settings.advisory_timeout_seconds,
        client=client,
        cache=TtlCache[tuple[Advisory, ...]](ttl_seconds=settings.advisory_cache_ttl_seconds),
        limiter=RateLimiter(
            capacity=settings.advisory_rate_limit_per_window,
            per_second=(
                settings.advisory_rate_limit_per_window
                / settings.advisory_rate_limit_window_seconds
            ),
        ),
        breaker=CircuitBreaker(
            failure_threshold=settings.advisory_breaker_failure_threshold,
            reset_seconds=settings.advisory_breaker_reset_seconds,
            name="github_advisories",
        ),
    )

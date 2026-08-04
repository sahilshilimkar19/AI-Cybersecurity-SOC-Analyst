"""National Vulnerability Database adapter (SAD §2.3, §7; EDS §3.12).

The live CVE feed. Like every data-source adapter it is **read-only**, wrapped in
the shared cache / rate limiter / circuit breaker, and returns typed failures
rather than raising — one feed's outage degrades vulnerability research and
nothing else (invariant #6).

Two things here are specific to CVE data rather than generic adapter plumbing:

* **Affected ranges are parsed out of CPE match criteria, not guessed.** NVD
  publishes what it actually knows: a product identifier plus optional version
  bounds. Those bounds are the entire basis on which the agent may later confirm
  that a host is exposed, so they are carried through verbatim — including the
  case where NVD publishes a product with *no* bounds, which means every version
  and is a real statement rather than missing data.
* **Only ``vulnerable`` match criteria are collected.** A CPE node also lists
  *running-on* platforms that are context, not exposure. Treating those as
  affected products would confirm applicability against the wrong software.

The default source is :class:`UnavailableCveSource`. NVD is reachable without an
API key, but whether this platform makes outbound calls at all is an operator's
decision, not a default — and with no live source the agent falls back to the
indexed corpus and marks the dossier stale, which is the documented degraded
path rather than an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

import httpx

from config.logging import get_logger
from integrations.resilience import BreakerState, CircuitBreaker, RateLimiter, TtlCache
from models.vulnerability import AffectedRange, CveDataSource, CveRecord, CvssMetrics
from tools.cvss import interpret

if TYPE_CHECKING:
    from collections.abc import Sequence

    from config.settings import Settings

_logger = get_logger(__name__)

# NVD's published limits: 5 requests per rolling 30 seconds without an API key,
# 50 with one. The limiter is configured from settings; these are the defaults.
_DEFAULT_WINDOW_SECONDS = 30.0
_DEFAULT_REQUESTS_PER_WINDOW = 5

# CPE 2.3 is a colon-delimited string; these are the fields we read.
_CPE_VENDOR_INDEX = 3
_CPE_PRODUCT_INDEX = 4

# CVSS metric blocks in NVD's response, best first. v2 is deliberately absent:
# the CVSS interpreter reads v3.x vectors, and a v2 vector scored as though it
# were v3 would be wrong rather than approximate.
_CVSS_KEYS = ("cvssMetricV31", "cvssMetricV30")


@dataclass(frozen=True)
class CveLookupFailure:
    """A lookup that did not happen, and why."""

    query: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class CveLookupResult:
    """Either records or a typed failure — never both, never neither."""

    records: tuple[CveRecord, ...] = ()
    failure: CveLookupFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None

    @classmethod
    def succeed(cls, records: Sequence[CveRecord]) -> CveLookupResult:
        return cls(records=tuple(records))

    @classmethod
    def fail(cls, query: str, reason: str, detail: str = "") -> CveLookupResult:
        return cls(failure=CveLookupFailure(query=query, reason=reason, detail=detail))


class CveSource(Protocol):
    """Read-only access to published vulnerability records."""

    @property
    def name(self) -> str: ...
    @property
    def is_available(self) -> bool: ...
    def fetch(self, cve_id: str) -> CveLookupResult: ...
    def search(self, keyword: str, *, limit: int = 10) -> CveLookupResult: ...


class UnavailableCveSource:
    """The default: no live CVE feed configured.

    Every lookup fails with a named reason so the agent records *why* it fell
    back to the indexed corpus, and marks the resulting dossier stale rather than
    presenting cached data as current.
    """

    @property
    def name(self) -> str:
        return "none"

    @property
    def is_available(self) -> bool:
        return False

    def fetch(self, cve_id: str) -> CveLookupResult:
        return CveLookupResult.fail(cve_id, "not_configured", "no live CVE feed is configured")

    def search(self, keyword: str, *, limit: int = 10) -> CveLookupResult:
        return CveLookupResult.fail(keyword, "not_configured", "no live CVE feed is configured")


class InMemoryCveSource:
    """Fixture-driven source for tests and offline runs."""

    def __init__(
        self,
        records: Sequence[CveRecord] = (),
        *,
        failures: Sequence[str] = (),
        name: str = "in-memory-nvd",
        available: bool = True,
    ) -> None:
        self._records = list(records)
        self._failures = {item.lower() for item in failures}
        self._name = name
        self._available = available

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_available(self) -> bool:
        return self._available

    def fetch(self, cve_id: str) -> CveLookupResult:
        if cve_id.lower() in self._failures:
            return CveLookupResult.fail(cve_id, "unreachable")
        matched = [item for item in self._records if item.cve_id.lower() == cve_id.lower()]
        return CveLookupResult.succeed(matched)

    def search(self, keyword: str, *, limit: int = 10) -> CveLookupResult:
        if keyword.lower() in self._failures:
            return CveLookupResult.fail(keyword, "unreachable")
        needle = keyword.lower()
        matched = [
            item
            for item in self._records
            if needle in item.summary.lower()
            or needle in item.title.lower()
            or any(needle in affected.product.lower() for affected in item.affected)
        ]
        return CveLookupResult.succeed(matched[:limit])


class NvdCveSource:
    """NVD CVE API v2 adapter — read-only, cached, rate-limited, breaker-guarded."""

    def __init__(
        self,
        *,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        api_key: str = "",
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
        cache: TtlCache[tuple[CveRecord, ...]] | None = None,
        limiter: RateLimiter | None = None,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._client = client
        self._cache = (
            cache if cache is not None else TtlCache[tuple[CveRecord, ...]](ttl_seconds=21_600)
        )
        self._limiter = limiter or RateLimiter(
            capacity=_DEFAULT_REQUESTS_PER_WINDOW,
            per_second=_DEFAULT_REQUESTS_PER_WINDOW / _DEFAULT_WINDOW_SECONDS,
        )
        self._breaker = breaker or CircuitBreaker(name="nvd")

    @property
    def name(self) -> str:
        return "nvd"

    @property
    def is_available(self) -> bool:
        """Whether the feed is usable right now.

        Reads the breaker's state rather than calling ``allow()`` — asking
        whether a source is usable must not consume the half-open probe an actual
        lookup is entitled to.
        """
        return self._breaker.state is not BreakerState.OPEN

    def fetch(self, cve_id: str) -> CveLookupResult:
        """Fetch one CVE by identifier."""
        return self._query({"cveId": cve_id}, cache_key=f"id:{cve_id.upper()}", label=cve_id)

    def search(self, keyword: str, *, limit: int = 10) -> CveLookupResult:
        """Search the feed by keyword, newest-modified first."""
        return self._query(
            {"keywordSearch": keyword, "resultsPerPage": str(limit)},
            cache_key=f"kw:{keyword.lower()}:{limit}",
            label=keyword,
        )

    # --- Internals --------------------------------------------------------

    def _query(self, params: dict[str, str], *, cache_key: str, label: str) -> CveLookupResult:
        cached = self._cache.get(cache_key)
        if cached is not None:
            return CveLookupResult.succeed(cached)

        if not self._breaker.allow():
            return self._degrade(cache_key, label, "circuit_open", "the NVD circuit is open")
        if not self._limiter.try_acquire():
            return self._degrade(cache_key, label, "rate_limited", "local NVD rate limit reached")

        try:
            response = self._get(params)
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            _logger.warning("nvd_unreachable", query=label)
            return self._degrade(cache_key, label, "unreachable", str(exc))

        if response.status_code != httpx.codes.OK:
            self._breaker.record_failure()
            return self._degrade(
                cache_key, label, "http_error", f"NVD returned {response.status_code}"
            )

        try:
            records = tuple(parse_nvd_response(response.json()))
        except (ValueError, KeyError, TypeError) as exc:
            self._breaker.record_failure()
            return self._degrade(cache_key, label, "malformed_response", str(exc))

        self._breaker.record_success()
        self._cache.set(cache_key, records)
        return CveLookupResult.succeed(records)

    def _get(self, params: dict[str, str]) -> httpx.Response:
        headers = {"accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        if self._client is not None:
            return self._client.get(
                self._base_url, params=params, headers=headers, timeout=self._timeout
            )
        with httpx.Client(timeout=self._timeout) as client:
            return client.get(self._base_url, params=params, headers=headers)

    def _degrade(self, cache_key: str, label: str, reason: str, detail: str) -> CveLookupResult:
        """Serve an expired cached answer, marked stale, or fail cleanly."""
        stale = self._cache.get_stale(cache_key)
        if stale is not None:
            return CveLookupResult.succeed(
                tuple(record.model_copy(update={"stale": True}) for record in stale)
            )
        return CveLookupResult.fail(label, reason, detail)


def parse_nvd_response(payload: Any) -> list[CveRecord]:
    """Parse an NVD v2 response into records, validating it as untrusted input."""
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise TypeError("NVD response has no 'vulnerabilities' list")

    records: list[CveRecord] = []
    for item in vulnerabilities:
        cve = (item or {}).get("cve")
        if isinstance(cve, dict) and cve.get("id"):
            records.append(_parse_cve(cve))
    return records


def _parse_cve(cve: dict[str, Any]) -> CveRecord:
    summary = _english_description(cve.get("descriptions"))
    return CveRecord(
        cve_id=str(cve["id"]),
        title=_title(str(cve["id"]), summary),
        summary=summary,
        cvss=_parse_cvss(cve.get("metrics")),
        cwe_ids=_parse_weaknesses(cve.get("weaknesses")),
        affected=_parse_configurations(cve.get("configurations")),
        references=_parse_references(cve.get("references")),
        published_at=_parse_timestamp(cve.get("published")),
        modified_at=_parse_timestamp(cve.get("lastModified")),
        source=CveDataSource.NVD,
    )


def _english_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            return str(entry.get("value", "")).strip()
    return ""


def _title(cve_id: str, summary: str) -> str:
    """A short label: the first sentence of the description, or the identifier."""
    if not summary:
        return cve_id
    first = summary.split(". ")[0].strip()
    return first if len(first) <= 160 else f"{first[:157]}..."


def _parse_cvss(metrics: Any) -> CvssMetrics | None:
    """Read the best available CVSS v3.x block through the shared interpreter."""
    if not isinstance(metrics, dict):
        return None
    for key in _CVSS_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        data = (entries[0] or {}).get("cvssData")
        if not isinstance(data, dict):
            continue
        vector = str(data.get("vectorString", ""))
        reported = data.get("baseScore")
        interpreted = interpret(
            vector, reported_score=float(reported) if isinstance(reported, int | float) else None
        )
        if interpreted is not None:
            return interpreted
    return None


def _parse_weaknesses(weaknesses: Any) -> list[str]:
    if not isinstance(weaknesses, list):
        return []
    found: list[str] = []
    for entry in weaknesses:
        for description in (entry or {}).get("description", []):
            value = str((description or {}).get("value", "")).strip()
            if value and value not in found:
                found.append(value)
    return found


def _parse_configurations(configurations: Any) -> list[AffectedRange]:
    """Collect the vulnerable CPE matches, ignoring running-on platform context."""
    if not isinstance(configurations, list):
        return []

    ranges: list[AffectedRange] = []
    for configuration in configurations:
        for node in (configuration or {}).get("nodes", []):
            for match in (node or {}).get("cpeMatch", []):
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                parsed = _parse_cpe_match(match)
                if parsed is not None:
                    ranges.append(parsed)
    return ranges


def _parse_cpe_match(match: dict[str, Any]) -> AffectedRange | None:
    parts = str(match.get("criteria", "")).split(":")
    if len(parts) <= _CPE_PRODUCT_INDEX:
        return None
    product = parts[_CPE_PRODUCT_INDEX].replace("_", " ").strip()
    if not product or product == "*":
        return None
    vendor = parts[_CPE_VENDOR_INDEX].replace("_", " ").strip() or None
    return AffectedRange(
        product=product,
        vendor=None if vendor == "*" else vendor,
        version_start_including=_optional(match.get("versionStartIncluding")),
        version_start_excluding=_optional(match.get("versionStartExcluding")),
        version_end_including=_optional(match.get("versionEndIncluding")),
        version_end_excluding=_optional(match.get("versionEndExcluding")),
    )


def _parse_references(references: Any) -> list[str]:
    if not isinstance(references, list):
        return []
    urls: list[str] = []
    for entry in references:
        url = str((entry or {}).get("url", "")).strip()
        if url and url not in urls:
            urls.append(url)
    return urls


def _parse_timestamp(value: Any) -> datetime | None:
    """Read an NVD timestamp, which is ISO-8601 without a zone and always UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _optional(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def build_cve_source(settings: Settings, *, client: httpx.Client | None = None) -> CveSource:
    """Compose the configured CVE source, defaulting to none.

    With no live source the agent researches from the indexed corpus and marks
    the dossier stale — the documented degraded path (EDS §4.4), not a failure.
    """
    if settings.cve_source != "nvd":
        return UnavailableCveSource()

    return NvdCveSource(
        base_url=settings.nvd_base_url,
        api_key=settings.nvd_api_key.get_secret_value(),
        timeout_seconds=settings.nvd_timeout_seconds,
        client=client,
        cache=TtlCache[tuple[CveRecord, ...]](ttl_seconds=settings.nvd_cache_ttl_seconds),
        limiter=RateLimiter(
            capacity=settings.nvd_rate_limit_per_window,
            per_second=settings.nvd_rate_limit_per_window / settings.nvd_rate_limit_window_seconds,
        ),
        breaker=CircuitBreaker(
            failure_threshold=settings.nvd_breaker_failure_threshold,
            reset_seconds=settings.nvd_breaker_reset_seconds,
            name="nvd",
        ),
    )

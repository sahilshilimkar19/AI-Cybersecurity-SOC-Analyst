"""Tests for the security advisory adapter.

The fixed version is the single most useful field in the response, so the parsing
assertions carry most of the weight — including the two different shapes the API
spells it in.
"""

import httpx
import pytest

from config.settings import Settings
from integrations.advisories import (
    Advisory,
    AdvisoryFix,
    GitHubAdvisorySource,
    InMemoryAdvisorySource,
    UnavailableAdvisorySource,
    build_advisory_source,
    parse_github_advisories,
)
from integrations.resilience import CircuitBreaker, RateLimiter, TtlCache
from tests.integrations.test_resilience import FakeClock

LOG4SHELL_PAYLOAD = [
    {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "cve_id": "CVE-2021-44228",
        "summary": "Remote code injection in Log4j",
        "severity": "critical",
        "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
        "published_at": "2021-12-10T00:00:00Z",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
                "vulnerable_version_range": ">= 2.0.1, < 2.3.2",
                "first_patched_version": "2.3.2",
            },
            {
                "package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-api"},
                "vulnerable_version_range": ">= 2.13.0, < 2.17.1",
                # The GraphQL shape: an object rather than a string.
                "first_patched_version": {"identifier": "2.17.1"},
            },
        ],
    }
]


def _transport(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


# --- Parsing ----------------------------------------------------------------


def test_an_advisory_parses_with_its_identity_and_source() -> None:
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)

    assert advisory.advisory_id == "GHSA-jfh8-c2jp-5v3q"
    assert advisory.cve_id == "CVE-2021-44228"
    assert advisory.severity == "critical"
    assert advisory.url.endswith("GHSA-jfh8-c2jp-5v3q")  # type: ignore[union-attr]


def test_the_fixed_version_is_read_from_both_api_shapes() -> None:
    """REST returns a string, GraphQL an object; dropping either loses the point."""
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    fixed = {fix.package: fix.fixed_version for fix in advisory.fixes}

    assert fixed["org.apache.logging.log4j:log4j-core"] == "2.3.2"
    assert fixed["org.apache.logging.log4j:log4j-api"] == "2.17.1"


def test_the_vulnerable_range_is_carried_through() -> None:
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    assert advisory.fixes[0].vulnerable_range == ">= 2.0.1, < 2.3.2"


def test_timestamps_are_timezone_aware() -> None:
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    assert advisory.published_at is not None
    assert advisory.published_at.tzinfo is not None


def test_an_entry_without_an_identifier_is_skipped() -> None:
    assert parse_github_advisories([{"summary": "no id"}, {}]) == []


def test_a_response_that_is_not_a_list_is_rejected() -> None:
    with pytest.raises(TypeError):
        parse_github_advisories({"message": "rate limited"})


def test_a_package_without_a_name_is_skipped() -> None:
    payload = [{"ghsa_id": "GHSA-x", "vulnerabilities": [{"package": {}}]}]
    (advisory,) = parse_github_advisories(payload)
    assert advisory.fixes == ()


# --- Matching a fix to a product --------------------------------------------


def test_the_fix_matching_the_product_is_preferred() -> None:
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    fix = advisory.fix_for("log4j-api")

    assert fix is not None
    assert fix.fixed_version == "2.17.1"


def test_an_unmatched_product_still_gets_an_answer() -> None:
    """An advisory listing one patched release for a family is usually right about it."""
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    fix = advisory.fix_for("something-unrelated")

    assert fix is not None
    assert fix.fixed_version == "2.3.2"


def test_an_advisory_with_no_patched_release_offers_no_fix() -> None:
    advisory = Advisory(
        advisory_id="GHSA-x", fixes=(AdvisoryFix(package="widget", fixed_version=None),)
    )
    assert advisory.fix_for("widget") is None


def test_an_advisory_cites_itself_resolvably() -> None:
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    citation = advisory.citation()

    assert citation.source_id == "vendor_advisories"
    assert citation.url == advisory.url
    assert citation.title == advisory.advisory_id


# --- Adapter behavior -------------------------------------------------------


def test_the_default_source_reports_itself_unavailable() -> None:
    source = UnavailableAdvisorySource()

    assert source.is_available is False
    result = source.fetch("CVE-2021-44228")
    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "not_configured"


def test_the_adapter_reads_and_never_writes() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(200, json=LOG4SHELL_PAYLOAD)

    GitHubAdvisorySource(client=_transport(handler)).fetch("CVE-2021-44228")
    assert methods == ["GET"]


def test_the_cve_is_sent_as_the_query() -> None:
    queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        queries.append(str(request.url.params))
        return httpx.Response(200, json=LOG4SHELL_PAYLOAD)

    GitHubAdvisorySource(client=_transport(handler)).fetch("CVE-2021-44228")
    assert "cve_id=CVE-2021-44228" in queries[0]


def test_a_token_is_sent_when_configured() -> None:
    headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers.get("authorization"))
        return httpx.Response(200, json=LOG4SHELL_PAYLOAD)

    GitHubAdvisorySource(token="secret", client=_transport(handler)).fetch("CVE-1")
    assert headers == ["Bearer secret"]


def test_a_repeat_lookup_is_served_from_cache() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=LOG4SHELL_PAYLOAD)

    source = GitHubAdvisorySource(client=_transport(handler))
    source.fetch("CVE-2021-44228")
    source.fetch("CVE-2021-44228")

    assert len(calls) == 1


def test_the_rate_limit_refuses_rather_than_calling() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=LOG4SHELL_PAYLOAD)

    source = GitHubAdvisorySource(
        client=_transport(handler),
        limiter=RateLimiter(capacity=1, per_second=0.0, clock=FakeClock()),
    )
    assert source.fetch("CVE-1").ok is True
    second = source.fetch("CVE-2")

    assert len(calls) == 1
    assert second.failure is not None
    assert second.failure.reason == "rate_limited"


def test_transport_errors_become_typed_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    result = GitHubAdvisorySource(client=_transport(handler)).fetch("CVE-1")

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "unreachable"


def test_repeated_failures_open_the_circuit() -> None:
    breaker = CircuitBreaker(failure_threshold=2, reset_seconds=60, clock=FakeClock())
    source = GitHubAdvisorySource(
        client=_transport(lambda request: httpx.Response(503)), breaker=breaker
    )
    source.fetch("CVE-1")
    source.fetch("CVE-2")

    assert source.is_available is False


def test_an_outage_serves_the_cached_advisory() -> None:
    """A published fixed version does not change, so a stale copy is as good."""
    clock = FakeClock()
    responses = [httpx.Response(200, json=LOG4SHELL_PAYLOAD), httpx.Response(503)]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    source = GitHubAdvisorySource(
        client=_transport(handler),
        cache=TtlCache[tuple[Advisory, ...]](ttl_seconds=10, clock=clock),
    )
    assert source.fetch("CVE-2021-44228").ok is True

    clock.advance(60)
    result = source.fetch("CVE-2021-44228")

    assert result.ok is True
    assert result.advisories[0].fixes[0].fixed_version == "2.3.2"


def test_a_malformed_response_is_a_failure_not_an_empty_answer() -> None:
    source = GitHubAdvisorySource(
        client=_transport(lambda request: httpx.Response(200, json={"unexpected": True}))
    )
    result = source.fetch("CVE-1")

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "malformed_response"


# --- In-memory source and composition ---------------------------------------


def test_the_in_memory_source_matches_by_cve() -> None:
    (advisory,) = parse_github_advisories(LOG4SHELL_PAYLOAD)
    source = InMemoryAdvisorySource(advisories=[advisory])

    assert source.fetch("cve-2021-44228").advisories
    assert source.fetch("CVE-2022-3602").advisories == ()


def test_the_in_memory_source_can_simulate_a_failure() -> None:
    source = InMemoryAdvisorySource(failures=frozenset({"CVE-1"}))
    assert source.fetch("CVE-1").ok is False


def test_the_default_configuration_yields_no_advisory_source() -> None:
    assert isinstance(build_advisory_source(Settings()), UnavailableAdvisorySource)


def test_a_configured_source_is_built_and_works_without_a_token() -> None:
    source = build_advisory_source(Settings(advisory_source="github"))

    assert isinstance(source, GitHubAdvisorySource)
    assert source.is_available is True


def test_the_token_is_never_exposed_in_settings_repr() -> None:
    settings = Settings(advisory_source="github", github_token="super-secret")
    assert "super-secret" not in repr(settings)

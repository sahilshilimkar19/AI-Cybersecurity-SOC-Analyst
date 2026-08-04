"""Tests for threat-intelligence enrichment.

The rule these guard is the one the whole module exists for: a reputation is only
ever set together with the source that asserted it. Every failure path is
therefore checked for what it must *not* produce.
"""

import httpx
import pytest

from config.settings import Settings
from integrations.resilience import CircuitBreaker, RateLimiter, TtlCache
from integrations.threat_intel import (
    InMemoryReputationProvider,
    ReputationVerdict,
    UnavailableReputationProvider,
    VirusTotalReputationProvider,
    build_reputation_provider,
    classify_analysis_stats,
    enrich_indicators,
    url_identifier,
)
from models.enums import EnrichmentStatus
from models.threat import IocIndicator, IocReputation, IocType
from tests.integrations.test_resilience import FakeClock


def _ioc(
    value: str = "203.0.113.9",
    *,
    ioc_type: IocType = IocType.IP_ADDRESS,
    internal: bool = False,
) -> IocIndicator:
    return IocIndicator(
        type=ioc_type,
        value=value,
        defanged=value.replace(".", "[.]"),
        event_ids=["e1"],
        internal=internal,
    )


def _transport(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def _stats_response(**stats: int) -> httpx.Response:
    return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})


# --- The default: nothing configured ----------------------------------------


def test_the_default_provider_reports_itself_unavailable() -> None:
    provider = UnavailableReputationProvider()
    assert provider.is_available is False


def test_an_unconfigured_lookup_fails_with_a_reason_not_a_clean_verdict() -> None:
    """Silence must be legible as silence, never as 'nothing found, so fine'."""
    result = UnavailableReputationProvider().lookup(_ioc())
    assert result.ok is False
    assert result.verdict is None
    assert result.failure is not None
    assert result.failure.reason == "not_configured"


def test_enrichment_without_a_provider_leaves_indicators_unknown() -> None:
    iocs, status, notes = enrich_indicators([_ioc()], UnavailableReputationProvider())

    assert status is EnrichmentStatus.UNAVAILABLE
    assert iocs[0].reputation is IocReputation.UNKNOWN
    assert iocs[0].enriched is False
    assert iocs[0].reputation_source is None
    assert notes


# --- Enrichment behavior ----------------------------------------------------


def test_a_successful_lookup_records_the_reputation_with_its_source() -> None:
    provider = InMemoryReputationProvider({"203.0.113.9": IocReputation.MALICIOUS})
    iocs, status, _ = enrich_indicators([_ioc()], provider)

    assert status is EnrichmentStatus.COMPLETE
    assert iocs[0].reputation is IocReputation.MALICIOUS
    assert iocs[0].reputation_source == "in-memory-intel"
    assert iocs[0].enriched is True
    assert iocs[0].is_hostile is True


def test_internal_indicators_are_never_submitted() -> None:
    provider = InMemoryReputationProvider({"10.0.0.5": IocReputation.MALICIOUS})
    iocs, status, _ = enrich_indicators([_ioc("10.0.0.5", internal=True)], provider)

    assert iocs[0].enriched is False
    assert status is EnrichmentStatus.COMPLETE


def test_ineligible_indicator_kinds_are_skipped() -> None:
    provider = InMemoryReputationProvider()
    iocs, _, _ = enrich_indicators(
        [_ioc("/home/j/secret.key", ioc_type=IocType.FILE_PATH)], provider
    )
    assert iocs[0].enriched is False


def test_a_partial_failure_degrades_rather_than_aborting() -> None:
    provider = InMemoryReputationProvider(
        {"203.0.113.9": IocReputation.MALICIOUS}, failures={"198.51.100.7": "unreachable"}
    )
    iocs, status, notes = enrich_indicators([_ioc(), _ioc("198.51.100.7")], provider)

    assert status is EnrichmentStatus.DEGRADED
    assert iocs[0].enriched is True
    assert iocs[1].enriched is False
    assert any("198" in note for note in notes)


def test_total_failure_is_reported_as_unavailable() -> None:
    provider = InMemoryReputationProvider(failures={"203.0.113.9": "rate_limited"})
    _, status, _ = enrich_indicators([_ioc()], provider)
    assert status is EnrichmentStatus.UNAVAILABLE


def test_the_enrichment_budget_is_bounded_and_the_shortfall_is_declared() -> None:
    iocs = [_ioc(f"203.0.113.{index}") for index in range(5)]
    enriched, status, notes = enrich_indicators(iocs, InMemoryReputationProvider(), limit=2)

    assert sum(1 for ioc in enriched if ioc.enriched) == 2
    assert status is EnrichmentStatus.DEGRADED
    assert any("budget" in note for note in notes)


def test_nothing_eligible_is_complete_not_degraded() -> None:
    _, status, notes = enrich_indicators([], InMemoryReputationProvider())
    assert status is EnrichmentStatus.COMPLETE
    assert notes == []


# --- VirusTotal adapter -----------------------------------------------------


def test_engine_votes_require_corroboration_before_calling_something_malicious() -> None:
    assert classify_analysis_stats({"malicious": 5, "harmless": 60}) is IocReputation.MALICIOUS
    assert classify_analysis_stats({"malicious": 1, "harmless": 60}) is IocReputation.SUSPICIOUS
    assert classify_analysis_stats({"suspicious": 4, "harmless": 60}) is IocReputation.SUSPICIOUS
    assert classify_analysis_stats({"harmless": 60}) is IocReputation.HARMLESS
    assert classify_analysis_stats({}) is IocReputation.UNKNOWN


def test_url_identifier_is_unpadded_urlsafe_base64() -> None:
    assert url_identifier("http://evil.example/a") == "aHR0cDovL2V2aWwuZXhhbXBsZS9h"


def test_the_adapter_reads_and_never_writes() -> None:
    """A data source has no enforcement authority (SAD §7)."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return _stats_response(malicious=5, harmless=60)

    provider = VirusTotalReputationProvider(api_key="k", client=_transport(handler))
    provider.lookup(_ioc())

    assert seen == ["GET"]


@pytest.mark.parametrize(
    ("ioc", "expected"),
    [
        (_ioc("203.0.113.9"), "/ip_addresses/203.0.113.9"),
        (_ioc("evil.example", ioc_type=IocType.DOMAIN), "/domains/evil.example"),
        (_ioc("a" * 64, ioc_type=IocType.FILE_HASH), f"/files/{'a' * 64}"),
    ],
)
def test_each_indicator_kind_maps_to_its_v3_resource(ioc: IocIndicator, expected: str) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return _stats_response(harmless=60)

    VirusTotalReputationProvider(
        api_key="k", base_url="https://vt.test/api/v3", client=_transport(handler)
    ).lookup(ioc)

    assert paths == [f"/api/v3{expected}"]


def test_an_unsupported_indicator_kind_fails_cleanly() -> None:
    provider = VirusTotalReputationProvider(api_key="k")
    result = provider.lookup(_ioc("cmd.exe", ioc_type=IocType.PROCESS))

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "unsupported"


def test_no_record_is_an_answer_of_unknown_not_a_failure() -> None:
    """Absence from VirusTotal is not evidence of innocence."""
    provider = VirusTotalReputationProvider(
        api_key="k", client=_transport(lambda request: httpx.Response(404))
    )
    result = provider.lookup(_ioc())

    assert result.ok is True
    assert result.verdict is not None
    assert result.verdict.reputation is IocReputation.UNKNOWN


def test_a_repeat_lookup_is_served_from_cache() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _stats_response(malicious=5, harmless=60)

    provider = VirusTotalReputationProvider(api_key="k", client=_transport(handler))
    provider.lookup(_ioc())
    provider.lookup(_ioc())

    assert len(calls) == 1


def test_the_rate_limit_refuses_rather_than_calling() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _stats_response(harmless=60)

    provider = VirusTotalReputationProvider(
        api_key="k",
        client=_transport(handler),
        limiter=RateLimiter(capacity=1, per_second=0.0, clock=FakeClock()),
    )
    assert provider.lookup(_ioc("203.0.113.1")).ok is True
    second = provider.lookup(_ioc("203.0.113.2"))

    assert len(calls) == 1
    assert second.ok is False
    assert second.failure is not None
    assert second.failure.reason == "rate_limited"


def test_transport_errors_become_typed_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    result = VirusTotalReputationProvider(api_key="k", client=_transport(handler)).lookup(_ioc())

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "unreachable"


def test_repeated_failures_open_the_circuit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    breaker = CircuitBreaker(failure_threshold=2, reset_seconds=60, clock=FakeClock())
    provider = VirusTotalReputationProvider(
        api_key="k", client=_transport(handler), breaker=breaker
    )
    provider.lookup(_ioc("203.0.113.1"))
    provider.lookup(_ioc("203.0.113.2"))

    assert provider.is_available is False
    assert provider.lookup(_ioc("203.0.113.3")).failure is not None


def test_checking_availability_does_not_consume_the_recovery_probe() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=30, clock=clock)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _stats_response(harmless=60)

    provider = VirusTotalReputationProvider(
        api_key="k", client=_transport(handler), breaker=breaker
    )
    breaker.record_failure()
    clock.advance(30)

    assert provider.is_available is True
    assert provider.is_available is True
    assert provider.lookup(_ioc()).ok is True
    assert len(calls) == 1


def test_an_outage_degrades_to_a_stale_cached_verdict_flagged_as_stale() -> None:
    clock = FakeClock()
    responses = [_stats_response(malicious=5, harmless=60), httpx.Response(500)]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    provider = VirusTotalReputationProvider(
        api_key="k",
        client=_transport(handler),
        cache=TtlCache[ReputationVerdict](ttl_seconds=10, clock=clock),
    )
    assert provider.lookup(_ioc()).ok is True

    clock.advance(60)
    result = provider.lookup(_ioc())

    assert result.ok is True
    assert result.verdict is not None
    assert result.verdict.stale is True
    assert result.verdict.reputation is IocReputation.MALICIOUS


def test_a_malformed_response_is_a_failure_not_a_verdict() -> None:
    provider = VirusTotalReputationProvider(
        api_key="k",
        client=_transport(lambda request: httpx.Response(200, json={"unexpected": True})),
    )
    result = provider.lookup(_ioc())

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "malformed_response"


def test_a_missing_api_key_is_not_a_half_working_provider() -> None:
    result = VirusTotalReputationProvider(api_key="").lookup(_ioc())
    assert result.failure is not None
    assert result.failure.reason == "not_configured"


# --- Composition ------------------------------------------------------------


def test_the_default_configuration_yields_no_provider() -> None:
    assert isinstance(build_reputation_provider(Settings()), UnavailableReputationProvider)


def test_virustotal_without_a_key_falls_back_rather_than_half_working() -> None:
    settings = Settings(threat_intel_provider="virustotal")
    assert isinstance(build_reputation_provider(settings), UnavailableReputationProvider)


def test_a_configured_provider_is_built() -> None:
    settings = Settings(threat_intel_provider="virustotal", virustotal_api_key="secret")
    provider = build_reputation_provider(settings)

    assert isinstance(provider, VirusTotalReputationProvider)
    assert provider.name == "virustotal"
    assert provider.is_available is True


def test_the_api_key_is_never_exposed_in_settings_repr() -> None:
    settings = Settings(threat_intel_provider="virustotal", virustotal_api_key="super-secret")
    assert "super-secret" not in repr(settings)

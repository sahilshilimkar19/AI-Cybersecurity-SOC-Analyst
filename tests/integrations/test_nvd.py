"""Tests for the NVD CVE feed adapter.

The parsing assertions matter more than they look: the affected version ranges
read out of CPE match criteria are the *entire* basis on which the agent may
later confirm that a host is exposed. Getting them wrong confirms the wrong
hosts.
"""

import httpx
import pytest

from config.settings import Settings
from integrations.nvd import (
    InMemoryCveSource,
    NvdCveSource,
    UnavailableCveSource,
    build_cve_source,
    parse_nvd_response,
)
from integrations.resilience import CircuitBreaker, RateLimiter, TtlCache
from models.enums import Severity
from models.vulnerability import CveDataSource, CveRecord
from tests.integrations.test_resilience import FakeClock

LOG4SHELL_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:39:23.747",
                "descriptions": [
                    {"lang": "es", "value": "Ignorado"},
                    {
                        "lang": "en",
                        "value": (
                            "Apache Log4j2 JNDI features do not protect against attacker "
                            "controlled LDAP. An attacker can execute arbitrary code."
                        ),
                    },
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0",
                                        "versionEndExcluding": "2.15.0",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                    },
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                ],
            }
        }
    ]
}


def _transport(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def _ok(payload: object) -> httpx.Response:
    return httpx.Response(200, json=payload)


# --- Parsing ----------------------------------------------------------------


def test_a_record_parses_into_the_domain_contract() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)

    assert record.cve_id == "CVE-2021-44228"
    assert record.source is CveDataSource.NVD
    assert record.stale is False
    assert "attacker controlled LDAP" in record.summary
    assert record.cwe_ids == ["CWE-502"]


def test_the_english_description_is_selected() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)
    assert "Ignorado" not in record.summary


def test_the_title_is_the_first_sentence() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)
    assert record.title.endswith("controlled LDAP")


def test_cvss_is_read_through_the_shared_interpreter() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)

    assert record.cvss is not None
    assert record.cvss.base_score == 10.0
    assert record.cvss.severity is Severity.CRITICAL
    assert record.cvss.narrative


def test_affected_ranges_carry_the_published_bounds() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)

    (affected,) = record.affected
    assert affected.product == "log4j"
    assert affected.vendor == "apache"
    assert affected.version_start_including == "2.0"
    assert affected.version_end_excluding == "2.15.0"


def test_running_on_platforms_are_not_treated_as_affected_products() -> None:
    """A non-vulnerable CPE is context; confirming against it targets the wrong software."""
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)
    assert [item.product for item in record.affected] == ["log4j"]


def test_a_product_with_no_bounds_is_kept_as_an_unbounded_range() -> None:
    """ "All versions" is a published statement, not missing data."""
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [{"lang": "en", "value": "test"}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    (record,) = parse_nvd_response(payload)
    assert record.affected[0].is_unbounded


def test_references_are_deduplicated() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)
    assert len(record.references) == 1


def test_timestamps_without_a_zone_are_read_as_utc() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)

    assert record.published_at is not None
    assert record.published_at.tzinfo is not None
    assert record.published_at.year == 2021


def test_a_cvss_v2_only_record_carries_no_metrics_rather_than_wrong_ones() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2005-0001",
                    "descriptions": [{"lang": "en", "value": "ancient"}],
                    "metrics": {
                        "cvssMetricV2": [
                            {"cvssData": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}
                        ]
                    },
                }
            }
        ]
    }
    (record,) = parse_nvd_response(payload)
    assert record.cvss is None


def test_a_response_without_a_vulnerabilities_list_is_rejected() -> None:
    with pytest.raises(TypeError):
        parse_nvd_response({"message": "rate limited"})


def test_entries_without_an_identifier_are_skipped() -> None:
    assert parse_nvd_response({"vulnerabilities": [{"cve": {}}, {}]}) == []


# --- Adapter behavior -------------------------------------------------------


def test_the_default_source_reports_itself_unavailable() -> None:
    source = UnavailableCveSource()

    assert source.is_available is False
    result = source.fetch("CVE-2021-44228")
    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "not_configured"


def test_the_adapter_reads_and_never_writes() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return _ok(LOG4SHELL_PAYLOAD)

    NvdCveSource(client=_transport(handler)).fetch("CVE-2021-44228")
    assert methods == ["GET"]


def test_fetch_queries_by_identifier_and_search_by_keyword() -> None:
    queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        queries.append(str(request.url.params))
        return _ok(LOG4SHELL_PAYLOAD)

    source = NvdCveSource(client=_transport(handler))
    source.fetch("CVE-2021-44228")
    source.search("log4j", limit=3)

    assert "cveId=CVE-2021-44228" in queries[0]
    assert "keywordSearch=log4j" in queries[1]
    assert "resultsPerPage=3" in queries[1]


def test_an_api_key_is_sent_when_configured() -> None:
    headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers.get("apikey"))
        return _ok(LOG4SHELL_PAYLOAD)

    NvdCveSource(api_key="secret", client=_transport(handler)).fetch("CVE-2021-44228")
    assert headers == ["secret"]


def test_a_repeat_lookup_is_served_from_cache() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _ok(LOG4SHELL_PAYLOAD)

    source = NvdCveSource(client=_transport(handler))
    source.fetch("CVE-2021-44228")
    source.fetch("CVE-2021-44228")

    assert len(calls) == 1


def test_the_rate_limit_refuses_rather_than_calling() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _ok(LOG4SHELL_PAYLOAD)

    source = NvdCveSource(
        client=_transport(handler),
        limiter=RateLimiter(capacity=1, per_second=0.0, clock=FakeClock()),
    )
    assert source.fetch("CVE-2021-44228").ok is True
    second = source.fetch("CVE-2022-3602")

    assert len(calls) == 1
    assert second.failure is not None
    assert second.failure.reason == "rate_limited"


def test_transport_errors_become_typed_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure")

    result = NvdCveSource(client=_transport(handler)).fetch("CVE-2021-44228")

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "unreachable"


def test_repeated_failures_open_the_circuit() -> None:
    breaker = CircuitBreaker(failure_threshold=2, reset_seconds=60, clock=FakeClock())
    source = NvdCveSource(client=_transport(lambda request: httpx.Response(503)), breaker=breaker)
    source.fetch("CVE-1")
    source.fetch("CVE-2")

    assert source.is_available is False


def test_an_outage_degrades_to_stale_cached_records() -> None:
    clock = FakeClock()
    responses = [_ok(LOG4SHELL_PAYLOAD), httpx.Response(503)]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    source = NvdCveSource(
        client=_transport(handler),
        cache=TtlCache[tuple[CveRecord, ...]](ttl_seconds=10, clock=clock),
    )
    assert source.fetch("CVE-2021-44228").ok is True

    clock.advance(60)
    result = source.fetch("CVE-2021-44228")

    assert result.ok is True
    assert result.records[0].stale is True


def test_a_malformed_response_is_a_failure_not_an_empty_result() -> None:
    source = NvdCveSource(
        client=_transport(lambda request: _ok({"unexpected": True})),
    )
    result = source.fetch("CVE-2021-44228")

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.reason == "malformed_response"


# --- In-memory source -------------------------------------------------------


def test_the_in_memory_source_matches_by_id_and_by_product() -> None:
    (record,) = parse_nvd_response(LOG4SHELL_PAYLOAD)
    source = InMemoryCveSource([record])

    assert source.fetch("cve-2021-44228").records[0].cve_id == "CVE-2021-44228"
    assert source.search("log4j").records
    assert source.search("postgres").records == ()


def test_the_in_memory_source_can_simulate_a_failure() -> None:
    source = InMemoryCveSource(failures=["log4j"])
    assert source.search("log4j").ok is False


# --- Composition ------------------------------------------------------------


def test_the_default_configuration_yields_no_live_source() -> None:
    assert isinstance(build_cve_source(Settings()), UnavailableCveSource)


def test_a_configured_source_is_built_and_works_without_an_api_key() -> None:
    """NVD is reachable unauthenticated; the key only raises the rate limit."""
    source = build_cve_source(Settings(cve_source="nvd"))

    assert isinstance(source, NvdCveSource)
    assert source.is_available is True


def test_the_api_key_is_never_exposed_in_settings_repr() -> None:
    settings = Settings(cve_source="nvd", nvd_api_key="super-secret")
    assert "super-secret" not in repr(settings)

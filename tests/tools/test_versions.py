"""Tests for version reasoning and CVE applicability.

The rule under test is the sprint's defining one: a CVE is not applicable until a
named host is shown to run a named product at a version inside a published
vulnerable range. Most of these assertions are about what must *not* be
confirmed.
"""

import pytest

from models.enums import CveApplicability
from models.vulnerability import (
    AffectedRange,
    ApplicabilityReason,
    AssetContext,
    AssetSoftware,
    CveRecord,
)
from tools.versions import (
    assess_applicability,
    in_vulnerable_range,
    normalize_product,
    parse_version,
    products_match,
)

LOG4J_RANGE = AffectedRange(
    product="log4j",
    vendor="apache",
    version_start_including="2.0",
    version_end_excluding="2.15.0",
)


def _record(*ranges: AffectedRange, cve_id: str = "CVE-2021-44228") -> CveRecord:
    return CveRecord(cve_id=cve_id, summary="test record", affected=list(ranges))


def _asset(product: str, version: str | None, *, hostname: str = "web-01") -> AssetContext:
    return AssetContext(
        hostname=hostname, software=[AssetSoftware(product=product, version=version)]
    )


# --- Parsing ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "release"),
    [
        ("1.2.3", (1, 2, 3)),
        ("v2.14.1", (2, 14, 1)),
        ("8.5.0.1", (8, 5, 0, 1)),
        ("1.2.3.RELEASE", (1, 2, 3)),
        ("10.0.19041.1", (10, 0, 19041, 1)),
        ("3.0.0-beta2", (3, 0, 0)),
    ],
)
def test_real_world_version_strings_parse(text: str, release: tuple[int, ...]) -> None:
    parsed = parse_version(text)
    assert parsed is not None
    assert parsed.release == release


@pytest.mark.parametrize("text", ["", None, "not-a-version", "latest", "unknown"])
def test_an_unreadable_version_refuses_rather_than_guessing(text: str | None) -> None:
    assert parse_version(text) is None


def test_a_prerelease_sorts_below_the_release_it_precedes() -> None:
    """ "Fixed in 2.0" does not mean a release candidate of 2.0 is fixed."""
    assert parse_version("2.0-rc1") < parse_version("2.0")  # type: ignore[operator]
    assert parse_version("2.0-rc1").is_prerelease  # type: ignore[union-attr]
    assert not parse_version("2.0").is_prerelease  # type: ignore[union-attr]


def test_prerelease_stages_order_by_maturity() -> None:
    order = ["3.0-dev", "3.0-alpha1", "3.0-beta1", "3.0-rc1", "3.0"]
    parsed = [parse_version(text) for text in order]
    assert parsed == sorted(parsed)  # type: ignore[type-var]


def test_numeric_segments_compare_numerically_not_lexically() -> None:
    assert parse_version("1.2.3") < parse_version("1.2.10")  # type: ignore[operator]


def test_a_release_qualifier_is_not_a_prerelease() -> None:
    assert parse_version("1.2.3.RELEASE") == parse_version("1.2.3")


# --- Product matching -------------------------------------------------------


def test_product_names_normalize_past_punctuation_and_case() -> None:
    assert normalize_product("Apache Log4j") == "apachelog4j"


@pytest.mark.parametrize(
    ("installed", "affected"),
    [
        ("Apache Log4j", "log4j-core"),
        ("log4j", "apache log4j"),
        ("OpenSSL", "openssl"),
        ("openssh-server", "OpenSSH"),
    ],
)
def test_inventory_and_advisory_spellings_match(installed: str, affected: str) -> None:
    assert products_match(installed, affected)


@pytest.mark.parametrize(
    ("installed", "affected"),
    [
        # Sharing only the vendor is not sharing a product.
        ("Apache HTTP Server", "Apache Tomcat"),
        ("nginx", "openssl"),
        # A short name must not match by containment.
        ("go", "google"),
        ("", "openssl"),
    ],
)
def test_unrelated_products_do_not_match(installed: str, affected: str) -> None:
    assert not products_match(installed, affected)


# --- Range membership -------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "expected"),
    [("2.0", True), ("2.14.1", True), ("2.15.0", False), ("1.9", False), ("3.0", False)],
)
def test_range_bounds_are_respected(version: str, expected: bool) -> None:
    parsed = parse_version(version)
    assert parsed is not None
    assert in_vulnerable_range(parsed, LOG4J_RANGE) is expected


def test_an_unbounded_range_means_every_version() -> None:
    every = AffectedRange(product="log4j")
    assert every.is_unbounded
    assert in_vulnerable_range(parse_version("9.9"), every) is True  # type: ignore[arg-type]


def test_exclusive_and_inclusive_start_bounds_differ() -> None:
    inclusive = AffectedRange(product="p", version_start_including="2.0")
    exclusive = AffectedRange(product="p", version_start_excluding="2.0")
    two = parse_version("2.0")
    assert in_vulnerable_range(two, inclusive) is True  # type: ignore[arg-type]
    assert in_vulnerable_range(two, exclusive) is False  # type: ignore[arg-type]


def test_an_unparseable_bound_is_undecidable_not_safe() -> None:
    """Collapsing "we could not tell" into "not affected" clears an unchecked host."""
    broken = AffectedRange(product="p", version_end_excluding="the-next-one")
    assert in_vulnerable_range(parse_version("1.0"), broken) is None  # type: ignore[arg-type]


# --- Applicability ----------------------------------------------------------


def test_host_product_and_version_together_confirm() -> None:
    applicability, evidence = assess_applicability(
        _record(LOG4J_RANGE), [_asset("Apache Log4j", "2.14.1")]
    )

    assert applicability is CveApplicability.CONFIRMED
    assert evidence[0].reason is ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE
    assert evidence[0].hostname == "web-01"
    assert evidence[0].installed_version == "2.14.1"


def test_a_version_outside_the_range_rules_the_cve_out() -> None:
    applicability, evidence = assess_applicability(
        _record(LOG4J_RANGE), [_asset("Apache Log4j", "2.17.1")]
    )

    assert applicability is CveApplicability.NOT_APPLICABLE
    assert evidence[0].reason is ApplicabilityReason.VERSION_NOT_IN_VULNERABLE_RANGE


def test_a_missing_version_is_a_candidate_that_says_what_to_go_and_check() -> None:
    applicability, evidence = assess_applicability(
        _record(LOG4J_RANGE), [_asset("Apache Log4j", None)]
    )

    assert applicability is CveApplicability.CANDIDATE
    assert evidence[0].reason is ApplicabilityReason.VERSION_UNKNOWN
    assert "records no version" in evidence[0].detail


def test_an_unreadable_version_is_a_candidate_not_a_confirmation() -> None:
    applicability, evidence = assess_applicability(
        _record(LOG4J_RANGE), [_asset("Apache Log4j", "nightly")]
    )

    assert applicability is CveApplicability.CANDIDATE
    assert evidence[0].reason is ApplicabilityReason.VERSION_UNPARSEABLE


def test_a_cve_with_no_published_range_can_never_be_confirmed() -> None:
    applicability, evidence = assess_applicability(_record(), [_asset("Apache Log4j", "2.14.1")])

    assert applicability is CveApplicability.CANDIDATE
    assert evidence[0].reason is ApplicabilityReason.NO_AFFECTED_RANGE_PUBLISHED


def test_a_product_absent_from_the_inventory_is_a_candidate() -> None:
    applicability, evidence = assess_applicability(
        _record(LOG4J_RANGE), [_asset("nginx", "1.24.0")]
    )

    assert applicability is CveApplicability.CANDIDATE
    assert evidence[0].reason is ApplicabilityReason.PRODUCT_NOT_IN_INVENTORY


def test_without_an_inventory_nothing_can_be_confirmed() -> None:
    """An unknown estate genuinely cannot support an applicability claim."""
    applicability, evidence = assess_applicability(_record(LOG4J_RANGE), [])

    assert applicability is CveApplicability.CANDIDATE
    assert "no asset inventory" in evidence[0].detail


def test_one_vulnerable_host_among_many_confirms_the_cve() -> None:
    assets = [
        _asset("Apache Log4j", "2.17.1", hostname="app-01"),
        _asset("Apache Log4j", "2.14.1", hostname="app-02"),
    ]
    applicability, evidence = assess_applicability(_record(LOG4J_RANGE), assets)

    assert applicability is CveApplicability.CONFIRMED
    confirming = [
        item for item in evidence if item.reason is ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE
    ]
    assert [item.hostname for item in confirming] == ["app-02"]


def test_evidence_is_kept_for_every_host_examined() -> None:
    """The negative results are the record that the other hosts were checked."""
    assets = [
        _asset("Apache Log4j", "2.17.1", hostname="app-01"),
        _asset("Apache Log4j", "2.14.1", hostname="app-02"),
    ]
    _, evidence = assess_applicability(_record(LOG4J_RANGE), assets)
    assert {item.hostname for item in evidence} == {"app-01", "app-02"}

"""Tests for the remediation guidance catalogue.

The catalogue's value is that it is pinned. Invented remediation steps are worse
than absent ones — plausible, specific, and wrong — so most of these assertions
are about what the catalogue refuses to make up.
"""

import re

import pytest

from models.enums import RecommendationType
from models.remediation import RemediationConfidence
from models.values import Citation
from tools.remediation import (
    INTERNAL_BASELINE_SOURCE_ID,
    MITIGATIONS,
    TEMPLATES,
    baseline_citation,
    for_technique,
    for_weakness,
    generic_guidance,
    patch_guidance,
)

_MITIGATION_ID = re.compile(r"^M\d{4}$")


# --- Catalogue integrity ----------------------------------------------------


def test_every_template_is_actionable_and_verifiable() -> None:
    """Guidance without steps is a slogan; without verification it is unfalsifiable."""
    for template in TEMPLATES.values():
        assert template.action, template.template_id
        assert template.rationale, template.template_id
        assert template.expected_impact, template.template_id
        assert template.steps, template.template_id
        assert template.verification, template.template_id


def test_every_template_carries_at_least_one_source() -> None:
    for template in TEMPLATES.values():
        assert template.citations(), template.template_id


def test_expected_impact_says_what_the_change_costs() -> None:
    """A change request that omits what it breaks gets applied and then reverted."""
    for template in TEMPLATES.values():
        if template.grounding is RemediationConfidence.GENERIC:
            continue
        assert len(template.expected_impact) > 40, template.template_id


def test_mitigation_identifiers_are_well_formed() -> None:
    for mitigation_id, mitigation in MITIGATIONS.items():
        assert _MITIGATION_ID.match(mitigation_id), mitigation_id
        assert mitigation.url.endswith(f"/{mitigation_id}/")
        assert mitigation.name


def test_no_template_contains_an_executable_payload() -> None:
    """The catalogue must never become one wiring change from an automation runner."""
    forbidden = re.compile(r"(?:^|\s)(?:sudo\s|rm\s+-rf|#!/|\$\(|`)", re.IGNORECASE)
    for template in TEMPLATES.values():
        for step in template.steps:
            assert not forbidden.search(step), f"{template.template_id}: {step}"


def test_no_template_frames_an_action_as_automatic() -> None:
    """Steps are written for a person; framing them as automatic invites a runner."""
    forbidden = ("automatically", "auto-remediate", "without approval", "the system will")
    for template in TEMPLATES.values():
        text = " ".join([template.action, *template.steps]).lower()
        for phrase in forbidden:
            assert phrase not in text, f"{template.template_id}: {phrase}"


# --- Technique and weakness mapping -----------------------------------------


@pytest.mark.parametrize(
    ("technique_id", "expected"),
    [
        ("T1110", "credential_attack_controls"),
        ("T1078", "credential_attack_controls"),
        ("T1027", "script_execution_controls"),
        ("T1070", "log_integrity"),
        ("T1562", "restore_security_tooling"),
        ("T1071", "egress_controls"),
        ("T1543", "persistence_review"),
    ],
)
def test_observed_techniques_map_to_their_mitigation(technique_id: str, expected: str) -> None:
    template = for_technique(technique_id)
    assert template is not None
    assert template.template_id == expected


def test_technique_lookup_is_case_insensitive() -> None:
    assert for_technique("t1110") is not None


def test_an_uncatalogued_technique_returns_nothing_rather_than_guessing() -> None:
    assert for_technique("T9999") is None


@pytest.mark.parametrize(
    ("cwe_id", "expected"),
    [
        ("CWE-502", "untrusted_input_handling"),
        ("CWE-89", "untrusted_input_handling"),
        ("CWE-862", "access_control_fix"),
        ("CWE-798", "access_control_fix"),
    ],
)
def test_weakness_classes_map_to_their_fix_pattern(cwe_id: str, expected: str) -> None:
    template = for_weakness(cwe_id)
    assert template is not None
    assert template.template_id == expected


def test_an_uncatalogued_weakness_returns_nothing() -> None:
    assert for_weakness("CWE-99999") is None


def test_technique_guidance_cites_mitre_mitigations() -> None:
    template = for_technique("T1110")
    assert template is not None
    assert all(
        citation.url and "attack.mitre.org/mitigations" in citation.url
        for citation in template.citations()
    )


# --- Generic fallback -------------------------------------------------------


def test_generic_guidance_is_labelled_generic() -> None:
    """Presenting general hardening as a fix is how a stopgap becomes permanent."""
    template = generic_guidance()
    assert template.grounding is RemediationConfidence.GENERIC
    assert "general hardening rather than a fix" in template.rationale


def test_generic_guidance_cites_the_internal_baseline() -> None:
    """Naming the baseline tells a reader the advice is ours, not a vendor's."""
    (citation,) = generic_guidance().citations()
    assert citation.source_id == INTERNAL_BASELINE_SOURCE_ID
    assert baseline_citation().source_id == INTERNAL_BASELINE_SOURCE_ID


def test_generic_guidance_says_the_real_fix_is_still_needed() -> None:
    assert "still required" in generic_guidance().expected_impact


# --- Patch guidance ---------------------------------------------------------


def test_a_known_fixed_version_is_stated_in_the_action() -> None:
    """Upgrade this to that is the strongest advice the system can give."""
    template = patch_guidance("CVE-2021-44228", product="log4j-core", fixed_version="2.17.1")

    assert "2.17.1" in template.action
    assert template.grounding is RemediationConfidence.VENDOR_SPECIFIC
    assert template.type is RecommendationType.PATCH


def test_without_a_fixed_version_the_guidance_stays_honest() -> None:
    """No version is invented; the advisory is named instead."""
    template = patch_guidance("CVE-2021-44228", product="log4j-core")

    assert "2.17" not in template.action
    assert template.grounding is RemediationConfidence.CLASS_SPECIFIC
    assert any("advisory" in step.lower() for step in template.steps)


def test_patch_guidance_carries_the_advisory_citation() -> None:
    advisory = Citation(
        source_id="vendor_advisories", source="GHSA", url="https://github.com/advisories/GHSA-x"
    )
    template = patch_guidance("CVE-2021-44228", fixed_version="2.17.1", advisory_citation=advisory)
    assert advisory in template.citations()


def test_patch_guidance_carries_the_records_references() -> None:
    template = patch_guidance(
        "CVE-2021-44228", references=["https://logging.apache.org/security.html"]
    )
    assert any(
        citation.url == "https://logging.apache.org/security.html"
        for citation in template.citations()
    )


def test_patch_guidance_bounds_how_many_references_it_carries() -> None:
    template = patch_guidance("CVE-1", references=[f"https://example/{n}" for n in range(10)])
    assert len(template.citations()) <= 5


def test_patch_guidance_verification_names_the_target() -> None:
    template = patch_guidance("CVE-1", product="openssl", fixed_version="3.0.7")
    assert "openssl" in template.verification
    assert "3.0.7" in template.verification


def test_citations_are_deduplicated_within_a_template() -> None:
    duplicate = Citation(source_id="a", source="A", url="https://same")
    template = patch_guidance("CVE-1", references=["https://same"], advisory_citation=duplicate)
    urls = [citation.url for citation in template.citations()]
    assert len(urls) == len(set(urls))

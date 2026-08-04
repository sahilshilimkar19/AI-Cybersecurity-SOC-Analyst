"""Tests for the incident report contracts.

The validator on :class:`ReportFinding` is the anti-fabrication rule expressed as
a type. These assertions guard it, because a rule enforced only in the reporter
is a rule the next caller can skip.
"""

import pytest
from pydantic import ValidationError

from models.enums import ReportStatus
from models.report import (
    CaveatKind,
    FindingSupport,
    IncidentReport,
    ReportCaveat,
    ReportFinding,
    ReportSectionKind,
)


def _finding(support: FindingSupport, section: ReportSectionKind = ReportSectionKind.THREAT):
    return ReportFinding(section=section, title="A finding", detail="Detail.", support=support)


# --- The support rule -------------------------------------------------------


@pytest.mark.parametrize(
    "support",
    [
        FindingSupport(event_ids=["e1"]),
        FindingSupport(signal_rule_ids=["brute_force"]),
        FindingSupport(technique_ids=["T1110"]),
        FindingSupport(cve_ids=["CVE-2021-44228"]),
        FindingSupport(indicator_values=["203[.]0[.]113[.]44"]),
    ],
)
def test_any_upstream_reference_is_enough_support(support: FindingSupport) -> None:
    assert _finding(support).support.is_empty is False


def test_a_finding_pointing_at_nothing_is_refused() -> None:
    """A fluent sentence that references nothing is indistinguishable from a real one."""
    with pytest.raises(ValidationError, match="cites no upstream support"):
        _finding(FindingSupport())


def test_empty_support_reports_itself_empty() -> None:
    assert FindingSupport().is_empty is True


# --- Completeness -----------------------------------------------------------


def test_a_report_with_no_missing_sections_is_complete() -> None:
    report = IncidentReport(
        investigation_id="inv-1",
        title="t",
        caveats=[
            ReportCaveat(
                kind=CaveatKind.COVERAGE_GAP,
                section=ReportSectionKind.EVIDENCE,
                detail="the SIEM was unreachable",
            )
        ],
    )
    assert report.is_complete is True


def test_a_missing_section_makes_a_report_incomplete() -> None:
    report = IncidentReport(
        investigation_id="inv-1",
        title="t",
        caveats=[
            ReportCaveat(
                kind=CaveatKind.MISSING_SECTION,
                section=ReportSectionKind.VULNERABILITY,
                detail="no research ran",
            )
        ],
    )
    assert report.is_complete is False


def test_findings_can_be_read_per_section() -> None:
    report = IncidentReport(
        investigation_id="inv-1",
        title="t",
        findings=[
            _finding(FindingSupport(event_ids=["e1"]), ReportSectionKind.EVIDENCE),
            _finding(FindingSupport(cve_ids=["CVE-1"]), ReportSectionKind.VULNERABILITY),
        ],
    )
    assert len(report.findings_in(ReportSectionKind.EVIDENCE)) == 1
    assert report.findings_in(ReportSectionKind.THREAT) == []


# --- Defaults ---------------------------------------------------------------


def test_a_report_defaults_to_a_draft_that_claims_nothing() -> None:
    report = IncidentReport(investigation_id="inv-1", title="t")

    assert report.status is ReportStatus.DRAFT
    assert report.verdict is None
    assert report.severity is None
    assert report.confidence == 0.0
    assert report.version == 1
    assert report.generated_from == []


def test_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        IncidentReport(investigation_id="inv-1", title="t", confidence=1.5)


def test_a_version_below_one_is_rejected() -> None:
    with pytest.raises(ValidationError):
        IncidentReport(investigation_id="inv-1", title="t", version=0)


def test_contracts_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        IncidentReport(investigation_id="inv-1", title="t", exective_summary="typo")  # type: ignore[call-arg]

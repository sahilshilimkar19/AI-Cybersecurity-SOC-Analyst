"""Tests for report rendering.

Rendering is a security boundary: almost everything in a report originates in
attacker-influenceable content. Most of these assertions are about hostile input
being *displayed* rather than *interpreted*.
"""

from datetime import UTC, datetime

import pytest

from models.enums import ReportStatus, Severity, Verdict
from models.report import (
    AffectedAsset,
    CaveatKind,
    FindingSupport,
    IncidentReport,
    ReportCaveat,
    ReportFinding,
    ReportSectionKind,
    ReportTimelineEntry,
)
from models.values import Citation
from tools.rendering import (
    escape_cell,
    fence,
    render_executive_summary,
    render_technical_body,
)

BASE = datetime(2026, 3, 4, 9, 0, tzinfo=UTC)


def _report(**overrides: object) -> IncidentReport:
    payload: dict[str, object] = {
        "investigation_id": "inv-1",
        "title": "Incident report",
        "verdict": Verdict.MALICIOUS,
        "severity": Severity.HIGH,
        "confidence": 0.82,
        "timeline": [
            ReportTimelineEntry(
                event_id="evt-1",
                occurred_at=BASE,
                source_id="hostlogs",
                summary="auth_failure: admin on web-01",
                raw_ref="auth.log#L1",
            )
        ],
        "findings": [
            ReportFinding(
                section=ReportSectionKind.THREAT,
                title="Repeated authentication failures",
                detail="Five failures for admin.",
                support=FindingSupport(event_ids=["evt-1"], signal_rule_ids=["brute_force"]),
                confidence=0.8,
            )
        ],
        "affected_assets": [AffectedAsset(hostname="web-01", event_count=5, critical=True)],
        "citations": [
            Citation(source_id="nvd", source="NVD", url="https://nvd.example/CVE-1", title="CVE-1")
        ],
    }
    payload.update(overrides)
    return IncidentReport(**payload)


# --- Escaping ---------------------------------------------------------------


def test_a_pipe_cannot_break_out_of_a_table_cell() -> None:
    assert "|" not in escape_cell("evil | injected | row")


def test_newlines_cannot_start_a_new_row() -> None:
    assert "\n" not in escape_cell("first line\nsecond line")
    assert "\r" not in escape_cell("carriage\r\nreturn")


@pytest.mark.parametrize(
    "hostile",
    ["# forged heading", "> forged quote", "- forged bullet", "1. forged item", "* forged"],
)
def test_markdown_structure_cannot_be_forged_at_the_start_of_a_value(hostile: str) -> None:
    escaped = escape_cell(hostile)
    assert escaped.startswith("\\")


def test_a_structural_character_mid_value_is_left_alone() -> None:
    """Escaping should neutralize structure, not mangle ordinary text."""
    assert escape_cell("exit code - 1") == "exit code - 1"


def test_an_enormous_value_is_bounded() -> None:
    escaped = escape_cell("A" * 5000)
    assert len(escaped) <= 200


def test_an_empty_value_renders_as_a_placeholder() -> None:
    assert escape_cell("") == "—"
    assert escape_cell(None) == "—"


def test_a_code_fence_cannot_be_closed_from_inside() -> None:
    """Without this, a log line with three backticks ends the block early."""
    block = fence("innocent\n```\n## now I am a heading")
    assert block.count("```") == 2
    assert "## now I am a heading" in block


# --- Executive summary ------------------------------------------------------


def test_the_summary_leads_with_the_disposition() -> None:
    summary = render_executive_summary(_report())
    assert "malicious" in summary
    assert "high" in summary


def test_the_summary_states_limitations_alongside_findings() -> None:
    """Caveats relegated to an appendix are caveats nobody reads."""
    summary = render_executive_summary(
        _report(
            caveats=[
                ReportCaveat(
                    kind=CaveatKind.COVERAGE_GAP,
                    section=ReportSectionKind.EVIDENCE,
                    detail="the SIEM was unreachable",
                )
            ]
        )
    )
    assert "1 stated limitation" in summary
    assert "Caveats" in summary


def test_the_summary_says_so_when_nothing_limited_it() -> None:
    assert "No limitations were recorded" in render_executive_summary(_report())


def test_the_summary_states_that_no_action_was_taken() -> None:
    """Invariant #2 has to survive into the document a manager reads."""
    assert "no action has been taken" in render_executive_summary(_report())


def test_the_summary_handles_an_investigation_with_no_assets() -> None:
    summary = render_executive_summary(_report(affected_assets=[]))
    assert "No affected asset could be identified" in summary


def test_the_summary_does_not_claim_confirmed_vulnerabilities_it_lacks() -> None:
    assert "No vulnerability was confirmed" in render_executive_summary(_report())


# --- Technical body ---------------------------------------------------------


def test_the_body_carries_every_section() -> None:
    body = render_technical_body(_report())
    for heading in (
        "## Overview",
        "## Timeline",
        "## Findings",
        "## Affected assets",
        "## Indicators of compromise",
        "## Adversary techniques",
        "## Vulnerabilities",
        "## Caveats",
        "## References",
    ):
        assert heading in body, heading


def test_an_empty_section_says_so_rather_than_disappearing() -> None:
    """ "No indicators were extracted" and an omitted section are different claims."""
    body = render_technical_body(_report(indicators=[], techniques=[], cves=[]))
    assert "No indicators were extracted" in body
    assert "No ATT&CK technique was mapped" in body
    assert "No vulnerability was confirmed applicable" in body


def test_findings_name_the_evidence_that_supports_them() -> None:
    body = render_technical_body(_report())
    assert "*Supported by:*" in body
    assert "`evt-1`" in body
    assert "`brute_force`" in body


def test_timeline_rows_carry_the_raw_reference() -> None:
    assert "auth.log#L1" in render_technical_body(_report())


def test_a_hostile_indicator_value_cannot_forge_a_table_row() -> None:
    body = render_technical_body(
        _report(
            indicators=[
                {
                    "type": "domain",
                    "defanged": "evil[.]test | ROGUE | ROW",
                    "reputation": "malicious",
                    "source": "vt",
                }
            ]
        )
    )
    assert "ROGUE" in body
    assert "| ROGUE |" not in body


def test_a_hostile_cve_summary_cannot_forge_a_heading() -> None:
    body = render_technical_body(
        _report(
            cves=[
                {
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "applicability": "confirmed",
                    "summary": "# Forged heading\nand a second line",
                }
            ]
        )
    )
    assert "\n# Forged heading" not in body
    assert "Forged heading" in body


def test_references_are_numbered_and_resolvable() -> None:
    body = render_technical_body(_report())
    assert "1. CVE-1 (NVD) — https://nvd.example/CVE-1" in body


def test_findings_carry_reference_marks_for_their_citations() -> None:
    citation = Citation(source_id="nvd", source="NVD", url="https://nvd.example/CVE-1")
    body = render_technical_body(
        _report(
            citations=[citation],
            findings=[
                ReportFinding(
                    section=ReportSectionKind.VULNERABILITY,
                    title="CVE-2021-44228 confirmed applicable",
                    detail="…",
                    support=FindingSupport(cve_ids=["CVE-2021-44228"]),
                    citations=[citation],
                )
            ],
        )
    )
    assert "[1]" in body


def test_the_overview_states_which_sections_the_report_rests_on() -> None:
    body = render_technical_body(
        _report(generated_from=[ReportSectionKind.EVIDENCE, ReportSectionKind.THREAT])
    )
    assert "| Assembled from | evidence, threat |" in body


def test_a_report_with_nothing_in_it_still_renders() -> None:
    body = render_technical_body(
        IncidentReport(investigation_id="inv-1", title="Empty", status=ReportStatus.DRAFT)
    )
    assert "No timeline could be reconstructed" in body
    assert "No findings were produced" in body
    assert "not assessed" in body


def test_rendering_is_deterministic() -> None:
    report = _report()
    assert render_technical_body(report) == render_technical_body(report)

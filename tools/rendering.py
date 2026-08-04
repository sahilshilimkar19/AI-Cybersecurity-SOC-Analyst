"""Rendering a structured incident report into a document (EDS §4.5).

The template renderer. It turns an :class:`~models.report.IncidentReport` into
Markdown for the two audiences the report has to serve at once — an executive who
needs the shape of the incident in a paragraph, and an engineer who needs the
timeline, the identifiers, and the references.

Rendering is a **security boundary**, which is easy to miss. Almost everything in
a report originates in attacker-influenceable content: log messages, process
command lines, indicator values, CVE descriptions. Written into Markdown
unescaped, a crafted log line can forge a heading, close a table and start prose
of its own, or open a code fence that swallows the rest of the document. Every
untrusted value therefore goes through :func:`escape_cell` or is fenced, so
hostile content is *displayed* rather than *interpreted* (invariant #3).

The renderer adds nothing. It reorders and formats what the agent assembled; if a
section is empty it says so, because "no indicators were extracted" and "the
indicators section was omitted" are different statements to a reader.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tools.reporting import citation_numbers, reference_marks

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.report import IncidentReport, ReportFinding
    from models.values import Citation

# Characters that would let untrusted text escape a table cell or a line.
_CELL_BREAKERS = re.compile(r"[|\r\n]+")

# Markdown structural prefixes neutralized at the start of an untrusted line, so
# a log message cannot forge a heading, a list, or a quote.
_LINE_STRUCTURE = re.compile(r"^(\s*)([#>\-*+]|\d+\.)(\s)")

# A backtick run long enough to close the fence this module opens.
_FENCE = "```"

_MAX_CELL = 200


def escape_cell(value: object, *, limit: int = _MAX_CELL) -> str:
    """Make an untrusted value safe to place inside a Markdown table cell.

    Collapses the characters that would end the cell or the row, neutralizes a
    leading structural marker, and bounds the length so one enormous log line
    cannot destroy the table's readability.

    A missing value renders as a placeholder rather than as the literal word
    "None" — which a reader cannot distinguish from a value that genuinely is
    the string "None".
    """
    if value is None:
        return "—"
    text = _CELL_BREAKERS.sub(" ", str(value)).strip()
    text = _LINE_STRUCTURE.sub(r"\1\\\2\3", text)
    if len(text) > limit:
        text = f"{text[: limit - 1]}…"
    return text or "—"


def fence(content: str, *, language: str = "text") -> str:
    """Wrap untrusted multi-line content in a code fence it cannot escape.

    Any fence-like run inside the content is neutralized first; without that, a
    log line containing three backticks would close the block and have its
    remainder rendered as document structure.
    """
    safe = content.replace(_FENCE, "'''")
    return f"{_FENCE}{language}\n{safe}\n{_FENCE}"


def render_executive_summary(report: IncidentReport) -> str:
    """The paragraph a manager reads.

    Leads with the disposition and the impact, states what is confirmed, and —
    deliberately in the same breath — states what is not. An executive summary
    that mentions only the findings is how a caveated investigation becomes a
    confident one somewhere between the analyst and the board.
    """
    verdict = report.verdict.value if report.verdict else "not assessed"
    severity = report.severity.value if report.severity else "unrated"
    hosts = [asset.hostname for asset in report.affected_assets]

    opening = (
        f"Investigation {report.investigation_id} was assessed as **{verdict}** "
        f"with **{severity}** severity."
    )
    scope = (
        f" Activity was observed across {len(hosts)} asset(s): "
        f"{', '.join(escape_cell(host, limit=60) for host in hosts[:5])}"
        + ("." if len(hosts) <= 5 else f", and {len(hosts) - 5} more.")
        if hosts
        else " No affected asset could be identified from the available evidence."
    )

    confirmed = len(report.cves)
    vulnerability = (
        f" {confirmed} vulnerability finding(s) were confirmed against these assets."
        if confirmed
        else " No vulnerability was confirmed against these assets."
    )

    caveats = (
        f" This report carries {len(report.caveats)} stated limitation(s); "
        "see Caveats before acting on it."
        if report.caveats
        else " No limitations were recorded on the evidence supporting this report."
    )

    closing = (
        f" Overall confidence in these findings is {report.confidence:.0%}. "
        "All conclusions are analytical recommendations for human review; "
        "no action has been taken."
    )
    return opening + scope + vulnerability + caveats + closing


def render_technical_body(report: IncidentReport) -> str:
    """The full technical document, in Markdown."""
    numbers = citation_numbers(report.citations)
    parts = [
        f"# {escape_cell(report.title, limit=120)}\n",
        _render_metadata(report),
        _render_timeline(report),
        _render_findings(report, numbers),
        _render_assets(report),
        _render_indicators(report),
        _render_techniques(report),
        _render_vulnerabilities(report),
        _render_caveats(report),
        _render_references(report.citations),
    ]
    return "\n".join(part for part in parts if part).rstrip() + "\n"


# --- Sections ---------------------------------------------------------------


def _render_metadata(report: IncidentReport) -> str:
    rows = [
        ("Investigation", report.investigation_id),
        ("Verdict", report.verdict.value if report.verdict else "not assessed"),
        ("Severity", report.severity.value if report.severity else "unrated"),
        ("Confidence", f"{report.confidence:.0%}"),
        ("Report version", str(report.version)),
        ("Status", report.status.value),
        ("Assembled from", ", ".join(item.value for item in report.generated_from) or "nothing"),
    ]
    body = "\n".join(f"| {label} | {escape_cell(value)} |" for label, value in rows)
    return f"## Overview\n\n| Field | Value |\n|---|---|\n{body}\n"


def _render_timeline(report: IncidentReport) -> str:
    if not report.timeline:
        return "## Timeline\n\nNo timeline could be reconstructed from the available evidence.\n"

    rows = "\n".join(
        f"| {entry.occurred_at.isoformat()} | {escape_cell(entry.source_id, limit=40)} "
        f"| {escape_cell(entry.summary)} | `{escape_cell(entry.event_id, limit=40)}` "
        f"| {escape_cell(entry.raw_ref or '—', limit=80)} |"
        for entry in report.timeline
    )
    return (
        "## Timeline\n\n| Time (UTC) | Source | Event | Event ID | Raw record |\n"
        f"|---|---|---|---|---|\n{rows}\n"
    )


def _render_findings(report: IncidentReport, numbers: dict[tuple[str, str], int]) -> str:
    if not report.findings:
        return "## Findings\n\nNo findings were produced by the investigation.\n"

    blocks: list[str] = ["## Findings", ""]
    for finding in report.findings:
        marks = reference_marks(finding.citations, numbers)
        blocks.append(
            f"### {escape_cell(finding.title, limit=120)} "
            f"({finding.section.value}, confidence {finding.confidence:.0%}){marks}"
        )
        blocks.append("")
        blocks.append(escape_cell(finding.detail, limit=2000))
        blocks.append("")
        blocks.append(f"*Supported by:* {_render_support(finding)}")
        blocks.append("")
    return "\n".join(blocks)


def _render_support(finding: ReportFinding) -> str:
    """Name the artifacts a claim rests on, so support can be followed."""
    support = finding.support
    parts: list[str] = []
    for label, values in (
        ("events", support.event_ids),
        ("detections", support.signal_rule_ids),
        ("techniques", support.technique_ids),
        ("CVEs", support.cve_ids),
        ("indicators", support.indicator_values),
    ):
        if values:
            shown = ", ".join(f"`{escape_cell(value, limit=60)}`" for value in values[:8])
            more = f" (+{len(values) - 8} more)" if len(values) > 8 else ""
            parts.append(f"{label} {shown}{more}")
    return "; ".join(parts) if parts else "—"


def _render_assets(report: IncidentReport) -> str:
    if not report.affected_assets:
        return "## Affected assets\n\nNo asset could be attributed from the evidence.\n"

    rows = "\n".join(
        f"| {escape_cell(asset.hostname, limit=80)} | {'yes' if asset.critical else 'no'} "
        f"| {asset.event_count} "
        f"| {escape_cell(', '.join(asset.confirmed_cve_ids) or '—', limit=120)} |"
        for asset in report.affected_assets
    )
    return (
        "## Affected assets\n\n| Host | Business-critical | Events | Confirmed CVEs |\n"
        f"|---|---|---|---|\n{rows}\n"
    )


def _render_indicators(report: IncidentReport) -> str:
    if not report.indicators:
        return "## Indicators of compromise\n\nNo indicators were extracted.\n"

    rows = "\n".join(
        f"| {escape_cell(item.get('type'), limit=20)} "
        f"| `{escape_cell(item.get('defanged') or item.get('value'), limit=120)}` "
        f"| {escape_cell(item.get('reputation'), limit=20)} "
        f"| {escape_cell(item.get('source') or 'not checked', limit=40)} |"
        for item in report.indicators
    )
    return (
        "## Indicators of compromise\n\nValues are defanged for safe handling.\n\n"
        f"| Type | Indicator | Reputation | Asserted by |\n|---|---|---|---|\n{rows}\n"
    )


def _render_techniques(report: IncidentReport) -> str:
    if not report.techniques:
        return "## Adversary techniques\n\nNo ATT&CK technique was mapped.\n"

    rows = "\n".join(
        f"| {escape_cell(item.get('technique_id'), limit=20)} "
        f"| {escape_cell(item.get('name'), limit=80)} "
        f"| {escape_cell(_join(item.get('tactics')), limit=80)} "
        f"| {escape_cell(item.get('rationale'), limit=160)} |"
        for item in report.techniques
    )
    return f"## Adversary techniques\n\n| ID | Name | Tactics | Why |\n|---|---|---|---|\n{rows}\n"


def _join(value: object) -> str:
    """Render a list-valued table field, tolerating a payload that is not a list."""
    return ", ".join(str(item) for item in value) if isinstance(value, list) else ""


def _render_vulnerabilities(report: IncidentReport) -> str:
    if not report.cves:
        return (
            "## Vulnerabilities\n\nNo vulnerability was confirmed applicable to the "
            "affected assets.\n"
        )

    rows = "\n".join(
        f"| {escape_cell(item.get('cve_id'), limit=24)} "
        f"| {escape_cell(item.get('cvss_score'), limit=8)} "
        f"| {escape_cell(item.get('applicability'), limit=24)} "
        f"| {escape_cell(item.get('summary'), limit=200)} |"
        for item in report.cves
    )
    return (
        "## Vulnerabilities\n\n| CVE | CVSS | Applicability | Summary |\n"
        f"|---|---|---|---|\n{rows}\n"
    )


def _render_caveats(report: IncidentReport) -> str:
    if not report.caveats:
        return "## Caveats\n\nNone recorded.\n"

    rows = "\n".join(
        f"- **{escape_cell(caveat.kind.value, limit=40)}** "
        f"({escape_cell(caveat.section.value, limit=20)}): {escape_cell(caveat.detail, limit=400)}"
        for caveat in report.caveats
    )
    return f"## Caveats\n\n{rows}\n"


def _render_references(citations: Sequence[Citation]) -> str:
    if not citations:
        return "## References\n\nNo external source was cited.\n"

    rows: list[str] = []
    for index, citation in enumerate(citations, start=1):
        label = escape_cell(citation.title or citation.source, limit=120)
        target = citation.url or citation.chunk_id
        suffix = f" — {escape_cell(target, limit=200)}" if target else ""
        rows.append(f"{index}. {label} ({escape_cell(citation.source, limit=60)}){suffix}")
    return "## References\n\n" + "\n".join(rows) + "\n"

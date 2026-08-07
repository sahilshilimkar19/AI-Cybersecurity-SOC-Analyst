"""Tests for alert rendering — the outbound escaping boundary.

Everything interesting in an alert came from a log line, and a log line is
attacker-influenceable (invariant #3). Each channel has its own way for that
content to stop being content, so each has its own tests: Slack's control
characters, email's header injection and reflexive linkification.

The tests are written as attacks rather than as formatting checks, because that
is what the escaping is for.
"""

from uuid import uuid4

import pytest

from models.enums import NotificationChannel, Severity, TriagePriority
from models.notification import AlertRequest
from tools.notifications import (
    MAX_SUBJECT,
    defang,
    escape_header,
    escape_plain,
    escape_slack,
    render,
    render_email,
    render_slack,
)


def _alert(**overrides: object) -> AlertRequest:
    payload: dict[str, object] = {
        "investigation_id": uuid4(),
        "approval_id": uuid4(),
        "title": "SSH brute force against web-01",
        "summary": "Six failures then a success for the same principal.",
        "priority": TriagePriority.URGENT,
        "severity": Severity.HIGH,
        "verdict": "malicious",
    }
    payload.update(overrides)
    return AlertRequest(**payload)


# --- Slack escaping ---------------------------------------------------------


def test_a_hostile_hostname_cannot_forge_a_slack_mention() -> None:
    """`<!channel>` in a log line would otherwise page an entire workspace."""
    rendered = render_slack(_alert(summary="host <!channel> was compromised"))

    assert "<!channel>" not in rendered.body
    assert "&lt;!channel&gt;" in rendered.body


def test_a_hostile_value_cannot_forge_a_slack_link() -> None:
    rendered = render_slack(_alert(title="<https://evil.test|Click here>"))

    assert "<https://evil.test|" not in rendered.body
    assert "&lt;" in rendered.body


def test_ampersands_are_escaped_before_the_angle_brackets_they_produce() -> None:
    """Escaping in the wrong order double-escapes and mangles the message."""
    assert escape_slack("a & b < c") == "a &amp; b &lt; c"


def test_slack_escaping_strips_control_characters() -> None:
    assert "\x00" not in escape_slack("web\x0001")


def test_a_slack_message_bounds_a_runaway_line() -> None:
    """One enormous log line must not push the actionable part off a phone."""
    assert len(escape_slack("x" * 5_000)) <= 400


# --- Email escaping ---------------------------------------------------------


def test_a_summary_cannot_inject_an_email_header() -> None:
    """CRLF in a subject is how an attacker appends a Bcc of their choosing."""
    subject = escape_header("Incident\r\nBcc: attacker@evil.test")

    assert "\r" not in subject
    assert "\n" not in subject
    assert "Bcc:" in subject  # rendered as text, on one line, not as a header


def test_the_subject_of_a_rendered_email_is_a_single_line() -> None:
    rendered = render_email(_alert(title="Breach\r\nBcc: attacker@evil.test"))

    assert "\r" not in rendered.subject
    assert "\n" not in rendered.subject
    assert len(rendered.subject) <= MAX_SUBJECT


def test_the_subject_carries_priority_and_severity_for_triage_by_subject_alone() -> None:
    rendered = render_email(_alert())

    assert "URGENT" in rendered.subject
    assert "high" in rendered.subject


def test_a_hostile_url_arrives_defanged() -> None:
    """An alert about a phishing link must not arrive as a clickable one."""
    rendered = render_email(_alert(summary="Credentials posted to https://evil.test/harvest"))

    assert "https://evil.test" not in rendered.body
    assert "https[://]evil.test" in rendered.body


def test_defanging_is_case_insensitive_and_covers_ftp() -> None:
    assert defang("HTTPS://evil.test") == "HTTPS[://]evil.test"
    assert defang("ftp://evil.test") == "ftp[://]evil.test"


def test_plain_text_escaping_collapses_tabs_and_newlines() -> None:
    assert escape_plain("a\tb\nc") == "a b c"


# --- Message content --------------------------------------------------------


def test_every_alert_says_that_nothing_was_executed() -> None:
    """An on-call reader must not infer from 'we alerted you' that it is handled."""
    assert "No remediation has been performed" in render_slack(_alert()).body
    assert "No remediation has been performed" in render_email(_alert()).body


def test_every_alert_says_a_human_approved_it() -> None:
    assert "approved" in render_slack(_alert()).body
    assert "approved" in render_email(_alert()).body


def test_highlights_reach_both_channels() -> None:
    alert = _alert(highlights=["Affected hosts: web-01", "Confirmed CVEs: CVE-2021-44228"])

    assert "CVE-2021-44228" in render_slack(alert).body
    assert "CVE-2021-44228" in render_email(alert).body


def test_the_console_link_is_carried_when_one_is_configured() -> None:
    alert = _alert(console_url="https://soc.example.com/investigations/abc")

    assert "soc.example.com" in render_slack(alert).body
    assert "Open the investigation" in render_email(alert).body


def test_an_alert_without_a_console_link_still_renders() -> None:
    """A deployment with no configured origin still has to be able to alert."""
    assert render_email(_alert()).body
    assert render_slack(_alert()).body


def test_a_slack_message_has_no_subject_because_slack_has_no_notion_of_one() -> None:
    assert render_slack(_alert()).subject == ""


def test_the_channel_selects_the_renderer() -> None:
    assert render(_alert(), NotificationChannel.SLACK).subject == ""
    assert render(_alert(), NotificationChannel.EMAIL).subject != ""


def test_an_unrated_severity_is_named_rather_than_omitted() -> None:
    """A blank in a subject line reads as an oversight, not as 'not assessed'."""
    assert "unrated" in render_email(_alert(severity=None)).subject


# --- Contract bounds --------------------------------------------------------


def test_an_alert_must_say_something() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="must say what happened"):
        _alert(summary="   ")


def test_an_alert_must_have_a_title() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="must have a title"):
        _alert(title=" ")


def test_an_alert_cannot_be_built_without_an_approval() -> None:
    """The field is required, so the accident is impossible before the check."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AlertRequest(  # type: ignore[call-arg]
            investigation_id=uuid4(),
            title="t",
            summary="s",
            priority=TriagePriority.HIGH,
        )

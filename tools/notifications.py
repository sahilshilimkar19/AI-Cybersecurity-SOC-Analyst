"""Rendering an alert for a channel (EDS §3.10 templating).

Deterministic templates, not prompts. An alert is a fixed shape filled with
investigation facts; there is no reason for a model to be anywhere near it, and
a generated alert would be one whose wording nobody could review in advance.

Like report rendering, this is a **security boundary**. Everything interesting in
an alert originates in attacker-influenceable content — hostnames from log lines,
indicator values, CVE summaries, an executive summary quoting a process command
line. Each channel has its own way for that content to stop being content:

* **Slack** interprets ``&``, ``<`` and ``>``. Left raw, a crafted hostname can
  forge a link or an ``<!channel>`` mention that pages an entire workspace.
* **Email** clients linkify anything that looks like a URL. An alert about a
  phishing link that arrives as a clickable phishing link has done the attacker's
  last step for them, so indicators are defanged and the message is sent as
  ``text/plain`` — never HTML, which would also make the alert a script host.

Both renderers bound every field. One enormous log line must not push the
actionable part of an alert past the point where a phone truncates it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from models.enums import NotificationChannel
from models.notification import RenderedMessage

if TYPE_CHECKING:
    from models.notification import AlertRequest

# Slack's control characters, escaped first-to-last so the ampersand rule cannot
# re-escape the output of the others.
_SLACK_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"))

# Anything that would end a header line or smuggle a second one into an email.
# Header injection is a real class: a summary containing CRLF could otherwise
# append a Bcc and quietly copy an incident to an attacker.
_HEADER_BREAKERS = re.compile(r"[\r\n\t]+")

# Control characters that terminals and mail clients handle inconsistently.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# The scheme prefix of a URL, so it can be rendered inert in plain text.
_URL_SCHEME = re.compile(r"\b(https?|ftp)://", re.IGNORECASE)

MAX_SUBJECT = 160
MAX_LINE = 400


def escape_slack(value: object, *, limit: int = MAX_LINE) -> str:
    """Make untrusted text safe to place in a Slack message.

    Escapes Slack's three control characters and bounds the length. Without this
    a hostname read out of a log line can forge a link, or an ``<!here>`` that
    notifies every person in the channel — which turns one hostile log entry into
    a workspace-wide page.
    """
    text = _CONTROL.sub("", str(value)).strip()
    for character, replacement in _SLACK_ESCAPES:
        text = text.replace(character, replacement)
    return _truncate(text, limit)


def escape_plain(value: object, *, limit: int = MAX_LINE) -> str:
    """Make untrusted text safe to place in a plain-text message body."""
    text = _CONTROL.sub("", str(value))
    text = _HEADER_BREAKERS.sub(" ", text).strip()
    return _truncate(text, limit)


def escape_header(value: object, *, limit: int = MAX_SUBJECT) -> str:
    """Make untrusted text safe to place in an email header.

    Collapses the characters that would terminate the header, because a newline
    in a subject line is a way to append headers of the attacker's choosing.
    """
    return escape_plain(value, limit=limit)


def defang(value: str) -> str:
    """Render a URL inert so a mail client will not turn it into a link.

    The indicators the platform stores are already defanged; this covers free
    text — a summary or a highlight — that may quote one anyway.
    """
    return _URL_SCHEME.sub(lambda match: f"{match.group(1)}[://]", value)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def render(alert: AlertRequest, channel: NotificationChannel) -> RenderedMessage:
    """Render an alert for one channel."""
    if channel is NotificationChannel.SLACK:
        return render_slack(alert)
    return render_email(alert)


def render_slack(alert: AlertRequest) -> RenderedMessage:
    """A short, scannable Slack message.

    Leads with priority and verdict, because the first line is all a phone's
    notification shows and it has to answer "do I open this now".
    """
    lines = [
        f"*{escape_slack(alert.priority.value.upper())}* — {escape_slack(alert.title, limit=200)}",
        _slack_facts(alert),
        escape_slack(defang(alert.summary), limit=800),
    ]
    lines.extend(f"• {escape_slack(defang(item))}" for item in alert.highlights)
    if alert.console_url:
        lines.append(f"Investigation: {escape_slack(alert.console_url, limit=300)}")
    lines.append("This alert was approved by an analyst. No remediation has been performed.")
    return RenderedMessage(body="\n".join(line for line in lines if line))


def _slack_facts(alert: AlertRequest) -> str:
    parts = [
        f"severity {escape_slack(alert.severity.value)}" if alert.severity else "",
        f"verdict {escape_slack(alert.verdict, limit=40)}" if alert.verdict else "",
        f"investigation {escape_slack(alert.investigation_id, limit=64)}",
    ]
    return " · ".join(part for part in parts if part)


def render_email(alert: AlertRequest) -> RenderedMessage:
    """A plain-text email.

    The subject carries priority and severity so a mailbox rule can act on it
    without parsing the body, and so a reader triaging by subject line alone is
    not misled about urgency.
    """
    severity = alert.severity.value if alert.severity else "unrated"
    subject = escape_header(f"[SOC {alert.priority.value.upper()}/{severity}] {alert.title}")

    lines = [
        escape_plain(defang(alert.summary), limit=1200),
        "",
        f"Priority:      {alert.priority.value}",
        f"Severity:      {severity}",
    ]
    if alert.verdict:
        lines.append(f"Verdict:       {escape_plain(alert.verdict, limit=40)}")
    lines.append(f"Investigation: {escape_plain(alert.investigation_id, limit=64)}")

    if alert.highlights:
        lines.extend(["", "Highlights:"])
        lines.extend(f"  - {escape_plain(defang(item))}" for item in alert.highlights)

    if alert.console_url:
        # Deliberately not a bare URL on its own line: some clients linkify
        # aggressively, and the console link is the one place we want a reader to
        # go deliberately rather than by reflex.
        lines.extend(["", f"Open the investigation: {escape_plain(alert.console_url, limit=300)}"])

    lines.extend(
        [
            "",
            "This alert was dispatched because an analyst approved the investigation.",
            "No remediation has been performed; recommendations await action by a person.",
        ]
    )
    return RenderedMessage(subject=subject, body="\n".join(lines))

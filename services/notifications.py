"""Who gets told, about what, and in what order (EDS §3.10).

Deterministic domain rules, kept out of both the adapters and the dispatcher so
they can be reasoned about and tested without a network or a database. The
dispatcher decides *how* to deliver; this decides *whether* and *where to*.

Three rules live here.

**Not everything is worth waking someone for.** An alert that fires on every
approved investigation trains its recipients to ignore it, and an ignored alert
channel is worse than no alert channel because it looks like coverage. Priority
is therefore a floor, set by the operator, and the default is high.

**Failover order is the operator's, not ours.** Which channel is tried first —
and what an outage falls back to — is a decision about how a particular SOC
works. This module honors the configured order; it does not invent one.

**A dedupe key is derived, never assigned.** Two callers computing a key for the
same delivery must get the same string, or the uniqueness constraint that makes
dispatch idempotent guards nothing. The key binds the *approval*, so re-running a
dispatch is a no-op while a genuinely new human decision can alert again — which
is the behavior you want after a redirect.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from models.enums import NotificationChannel, TriagePriority
from models.notification import AlertTarget

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from config.settings import Settings

# Ascending urgency. Comparing priorities by name is how a threshold quietly
# becomes alphabetical, so the order is stated once, here.
_PRIORITY_RANK: dict[TriagePriority, int] = {
    TriagePriority.LOW: 0,
    TriagePriority.MEDIUM: 1,
    TriagePriority.HIGH: 2,
    TriagePriority.URGENT: 3,
}


def priority_rank(priority: TriagePriority) -> int:
    """The urgency ordering, as a number."""
    return _PRIORITY_RANK[priority]


def is_worth_alerting(priority: TriagePriority, *, minimum: TriagePriority) -> bool:
    """Whether an investigation at ``priority`` clears the alerting floor.

    Suppression here is not a failure and must never be reported as one: nobody
    was told because nobody needed to be, and conflating that with a delivery
    failure is how a team stops trusting its dead-letter queue.
    """
    return priority_rank(priority) >= priority_rank(minimum)


def dedupe_key(
    *,
    investigation_id: UUID,
    approval_id: UUID,
    channel: NotificationChannel,
    recipient: str,
) -> str:
    """A stable identifier for one delivery of one approved alert.

    Bound to the approval rather than to the investigation, so:

    * re-running a dispatch for the same decision is idempotent — the uniqueness
      constraint on this key turns a duplicate into a no-op rather than into a
      second page at 3am;
    * a *new* decision on the same investigation, after a redirect and a second
      review, produces a different key and is free to alert again.

    Hashed rather than concatenated so the column has a fixed width and no
    delimiter that a recipient string could contain.
    """
    material = "|".join(
        [str(investigation_id), str(approval_id), channel.value, recipient.strip().lower()]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def resolve_targets(settings: Settings) -> list[AlertTarget]:
    """Expand the configured channels into concrete, ordered delivery targets.

    Returns an empty list when nothing is configured. That is a deployment
    choice, not a degradation: an unconfigured platform sends nothing and says
    so, exactly as an unconfigured threat-intel provider returns "unavailable"
    rather than "clean".

    Email fans out to every configured recipient, and each address is its own
    target: one bad address should cost that address, not the whole channel.
    """
    targets: list[AlertTarget] = []
    for channel in settings.notification_channel_order:
        if channel is NotificationChannel.SLACK:
            targets.append(
                AlertTarget(
                    channel=channel,
                    recipient=settings.slack_channel or "slack-webhook",
                )
            )
        elif channel is NotificationChannel.EMAIL:
            targets.extend(
                AlertTarget(channel=channel, recipient=address)
                for address in settings.email_recipients
            )
    return targets


def failover_plan(targets: Sequence[AlertTarget]) -> list[list[AlertTarget]]:
    """Group ordered targets into failover tiers, one tier per channel.

    Within a tier every target is attempted — three on-call addresses on the same
    channel are three people who each need the message, not three chances to
    reach one. Between tiers the next channel is only tried if the previous one
    reached nobody, which is what makes Slack→email a *fallback* rather than a
    duplicate page.
    """
    tiers: list[list[AlertTarget]] = []
    for target in targets:
        if tiers and tiers[-1][0].channel is target.channel:
            tiers[-1].append(target)
        else:
            tiers.append([target])
    return tiers

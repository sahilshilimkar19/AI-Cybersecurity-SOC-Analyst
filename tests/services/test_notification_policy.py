"""Tests for the deterministic notification policy.

No network, no database. What is pinned here is the arithmetic of alerting: who
clears the floor, which targets exist, what order they are tried in, and that two
callers computing a dedupe key for the same delivery agree — because the
uniqueness constraint that makes dispatch idempotent guards nothing if they do
not.
"""

import pytest

from config.settings import Settings
from models.enums import NotificationChannel, TriagePriority
from models.notification import AlertTarget
from services.notifications import (
    dedupe_key,
    failover_plan,
    is_worth_alerting,
    priority_rank,
    resolve_targets,
)

INVESTIGATION = "11111111-1111-1111-1111-111111111111"
APPROVAL = "22222222-2222-2222-2222-222222222222"


def _settings(**overrides: object) -> Settings:
    payload: dict[str, object] = {"log_json": False, "log_level": "WARNING"}
    payload.update(overrides)
    return Settings(**payload)  # type: ignore[arg-type]


# --- The alerting floor -----------------------------------------------------


def test_priority_is_ranked_by_urgency_not_alphabetically() -> None:
    """'urgent' sorts before 'high' alphabetically, and that would be wrong."""
    assert priority_rank(TriagePriority.URGENT) > priority_rank(TriagePriority.HIGH)
    assert priority_rank(TriagePriority.HIGH) > priority_rank(TriagePriority.MEDIUM)
    assert priority_rank(TriagePriority.MEDIUM) > priority_rank(TriagePriority.LOW)


@pytest.mark.parametrize(
    "priority,expected",
    [
        (TriagePriority.URGENT, True),
        (TriagePriority.HIGH, True),
        (TriagePriority.MEDIUM, False),
        (TriagePriority.LOW, False),
    ],
)
def test_the_floor_decides_who_is_worth_waking(priority: TriagePriority, expected: bool) -> None:
    """An alert that fires on everything trains its recipients to ignore it."""
    assert is_worth_alerting(priority, minimum=TriagePriority.HIGH) is expected


def test_the_floor_is_configurable_downward() -> None:
    assert is_worth_alerting(TriagePriority.LOW, minimum=TriagePriority.LOW) is True


# --- Dedupe keys ------------------------------------------------------------


def _key(**overrides: object) -> str:
    payload: dict[str, object] = {
        "investigation_id": INVESTIGATION,
        "approval_id": APPROVAL,
        "channel": NotificationChannel.SLACK,
        "recipient": "#soc-alerts",
    }
    payload.update(overrides)
    return dedupe_key(**payload)  # type: ignore[arg-type]


def test_the_same_delivery_always_derives_the_same_key() -> None:
    """Idempotency depends on two callers agreeing without coordinating."""
    assert _key() == _key()


def test_a_key_is_fixed_width_so_it_fits_its_column() -> None:
    assert len(_key()) == 64


@pytest.mark.parametrize(
    "difference",
    [
        {"investigation_id": "33333333-3333-3333-3333-333333333333"},
        {"approval_id": "44444444-4444-4444-4444-444444444444"},
        {"channel": NotificationChannel.EMAIL},
        {"recipient": "someone-else@example.com"},
    ],
)
def test_a_different_delivery_derives_a_different_key(difference: dict[str, object]) -> None:
    assert _key(**difference) != _key()


def test_a_new_decision_may_alert_again() -> None:
    """The key binds the approval, so a redirect and a second review can page."""
    first = _key(approval_id="55555555-5555-5555-5555-555555555555")
    second = _key(approval_id="66666666-6666-6666-6666-666666666666")
    assert first != second


def test_recipient_casing_and_padding_do_not_split_a_key() -> None:
    """Otherwise ' #SOC ' and '#soc' are two deliveries and someone gets two pages."""
    assert _key(recipient="  #SOC-Alerts ") == _key(recipient="#soc-alerts")


# --- Targets ----------------------------------------------------------------


def test_nothing_configured_yields_no_targets() -> None:
    """A deployment choice, not a degradation."""
    assert resolve_targets(_settings()) == []


def test_slack_resolves_to_its_channel_name() -> None:
    settings = _settings(
        notification_channels="slack",
        slack_webhook_url="https://hooks.slack.test/abc",
        slack_channel="#soc-alerts",
    )
    assert resolve_targets(settings) == [
        AlertTarget(channel=NotificationChannel.SLACK, recipient="#soc-alerts")
    ]


def test_email_fans_out_to_every_recipient() -> None:
    """One bad address should cost that address, not the whole channel."""
    settings = _settings(
        notification_channels="email",
        smtp_host="smtp.test",
        smtp_from_address="soc@example.com",
        smtp_recipients="a@example.com, b@example.com",
    )
    assert [target.recipient for target in resolve_targets(settings)] == [
        "a@example.com",
        "b@example.com",
    ]


def test_the_configured_order_is_preserved() -> None:
    """Which channel is tried first is the operator's decision, not ours."""
    settings = _settings(
        notification_channels="email,slack",
        slack_webhook_url="https://hooks.slack.test/abc",
        slack_channel="#soc",
        smtp_host="smtp.test",
        smtp_from_address="soc@example.com",
        smtp_recipients="a@example.com",
    )
    assert [target.channel for target in resolve_targets(settings)] == [
        NotificationChannel.EMAIL,
        NotificationChannel.SLACK,
    ]


def test_a_target_must_name_a_recipient() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="must name a recipient"):
        AlertTarget(channel=NotificationChannel.EMAIL, recipient="   ")


# --- Failover tiers ---------------------------------------------------------


def test_targets_on_one_channel_form_a_single_tier() -> None:
    """Three on-call addresses are three people, not three chances at one."""
    targets = [
        AlertTarget(channel=NotificationChannel.EMAIL, recipient="a@example.com"),
        AlertTarget(channel=NotificationChannel.EMAIL, recipient="b@example.com"),
    ]
    assert failover_plan(targets) == [targets]


def test_each_channel_is_its_own_fallback_tier() -> None:
    slack = AlertTarget(channel=NotificationChannel.SLACK, recipient="#soc")
    email = AlertTarget(channel=NotificationChannel.EMAIL, recipient="a@example.com")

    assert failover_plan([slack, email]) == [[slack], [email]]


def test_no_targets_means_no_tiers() -> None:
    assert failover_plan([]) == []

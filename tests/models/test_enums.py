"""Tests for enum string values (stable storage representations)."""

from models.enums import (
    ApprovalStatus,
    DecisionType,
    NotificationChannel,
    Severity,
    UserRole,
    Verdict,
)


def test_enum_values_are_lowercase_strings() -> None:
    assert UserRole.ANALYST.value == "analyst"
    assert Severity.CRITICAL.value == "critical"
    assert Verdict.MALICIOUS.value == "malicious"
    assert NotificationChannel.EMAIL.value == "email"
    assert ApprovalStatus.PENDING.value == "pending"
    assert DecisionType.REDIRECT.value == "redirect"


def test_str_enum_is_str() -> None:
    # StrEnum members compare/serialize as their string value.
    assert UserRole.ADMIN == "admin"
    assert f"{Severity.HIGH}" == "high"

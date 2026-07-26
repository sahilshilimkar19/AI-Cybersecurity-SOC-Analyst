"""Tests for domain contract validation and construction."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from models import (
    Cvss,
    Investigation,
    InvestigationStatus,
    LogEvent,
    Severity,
    ThreatAssessment,
    TriagePriority,
    TriggerSource,
    User,
    UserRole,
    UserStatus,
    Verdict,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _identity() -> dict[str, Any]:
    return {"id": uuid4(), "created_at": _now(), "updated_at": _now()}


def test_user_defaults() -> None:
    user = User(**_identity(), email="analyst@example.com", name="Ada", role=UserRole.ANALYST)

    assert user.status is UserStatus.ACTIVE
    assert user.deleted_at is None


def test_investigation_defaults() -> None:
    inv = Investigation(**_identity(), trigger_source=TriggerSource.ALERT)

    assert inv.status is InvestigationStatus.OPEN
    assert inv.config_snapshot == {}


def test_extra_fields_are_forbidden() -> None:
    payload: dict[str, Any] = {
        **_identity(),
        "email": "x@example.com",
        "name": "X",
        "role": UserRole.ANALYST,
        "unexpected": "nope",
    }
    with pytest.raises(ValidationError):
        User(**payload)


def test_confidence_must_be_within_unit_interval() -> None:
    with pytest.raises(ValidationError):
        ThreatAssessment(
            **_identity(),
            investigation_id=uuid4(),
            verdict=Verdict.MALICIOUS,
            severity=Severity.HIGH,
            triage_priority=TriagePriority.HIGH,
            confidence=1.5,
        )


def test_notability_must_be_within_unit_interval() -> None:
    with pytest.raises(ValidationError):
        LogEvent(
            **_identity(),
            investigation_id=uuid4(),
            source="auth",
            event_time=_now(),
            event_type="login_failed",
            notability=2.0,
        )


def test_cvss_score_range_enforced() -> None:
    Cvss(score=9.8, severity=Severity.CRITICAL)  # valid
    with pytest.raises(ValidationError):
        Cvss(score=11.0, severity=Severity.CRITICAL)


def test_from_attributes_builds_from_orm_like_object() -> None:
    row = SimpleNamespace(
        id=uuid4(),
        created_at=_now(),
        updated_at=_now(),
        email="row@example.com",
        name="Row",
        role=UserRole.SENIOR_ANALYST,
        sso_subject="sso-123",
        status=UserStatus.ACTIVE,
        deleted_at=None,
    )

    user = User.model_validate(row)

    assert user.email == "row@example.com"
    assert user.role is UserRole.SENIOR_ANALYST

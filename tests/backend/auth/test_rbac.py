"""Tests for role-based access control."""

from uuid import uuid4

import pytest

from backend.api.deps import require_capability
from backend.auth.errors import AuthorizationError
from backend.auth.rbac import Capability, capabilities_for, has_capability
from backend.auth.schemas import Principal
from models.enums import UserRole


def test_analyst_capabilities() -> None:
    caps = capabilities_for(UserRole.ANALYST)
    assert Capability.RUN_INVESTIGATIONS in caps
    assert Capability.APPROVE_ACTIONS not in caps
    assert Capability.MANAGE_USERS not in caps


def test_senior_analyst_can_approve() -> None:
    assert has_capability(UserRole.SENIOR_ANALYST, Capability.APPROVE_ACTIONS)


def test_admin_has_all_capabilities() -> None:
    assert capabilities_for(UserRole.ADMIN) == frozenset(Capability)


def test_auditor_is_read_only() -> None:
    caps = capabilities_for(UserRole.AUDITOR)
    assert Capability.VIEW_AUDIT in caps
    assert Capability.RUN_INVESTIGATIONS not in caps


def _principal(role: UserRole) -> Principal:
    return Principal(
        user_id=uuid4(),
        sso_subject="oidc|1",
        email="u@example.com",
        name="U",
        role=role,
        session_id="s",
    )


def test_require_capability_allows_permitted_role() -> None:
    dependency = require_capability(Capability.MANAGE_USERS)
    principal = _principal(UserRole.ADMIN)

    assert dependency(principal) is principal


def test_require_capability_denies_unpermitted_role() -> None:
    dependency = require_capability(Capability.MANAGE_USERS)

    with pytest.raises(AuthorizationError):
        dependency(_principal(UserRole.ANALYST))

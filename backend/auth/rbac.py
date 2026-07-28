"""Role-based access control.

Maps each RBAC role to the capabilities it grants. Access checks are expressed
in terms of capabilities so endpoints do not hard-code role lists (deny by
default; least privilege — SAD §14).
"""

from __future__ import annotations

from enum import StrEnum

from models.enums import UserRole


class Capability(StrEnum):
    """A discrete permission that can be granted to a role."""

    VIEW_INVESTIGATIONS = "view_investigations"
    RUN_INVESTIGATIONS = "run_investigations"
    APPROVE_ACTIONS = "approve_actions"
    VIEW_AUDIT = "view_audit"
    MANAGE_USERS = "manage_users"
    CONFIGURE = "configure"


ROLE_CAPABILITIES: dict[UserRole, frozenset[Capability]] = {
    UserRole.ANALYST: frozenset({Capability.VIEW_INVESTIGATIONS, Capability.RUN_INVESTIGATIONS}),
    UserRole.SENIOR_ANALYST: frozenset(
        {
            Capability.VIEW_INVESTIGATIONS,
            Capability.RUN_INVESTIGATIONS,
            Capability.APPROVE_ACTIONS,
        }
    ),
    UserRole.MANAGER: frozenset(
        {
            Capability.VIEW_INVESTIGATIONS,
            Capability.RUN_INVESTIGATIONS,
            Capability.APPROVE_ACTIONS,
            Capability.VIEW_AUDIT,
        }
    ),
    UserRole.ADMIN: frozenset(Capability),
    UserRole.AUDITOR: frozenset({Capability.VIEW_INVESTIGATIONS, Capability.VIEW_AUDIT}),
}


def capabilities_for(role: UserRole) -> frozenset[Capability]:
    """Return the capabilities granted to ``role``."""
    return ROLE_CAPABILITIES.get(role, frozenset())


def has_capability(role: UserRole, capability: Capability) -> bool:
    """Whether ``role`` grants ``capability``."""
    return capability in capabilities_for(role)

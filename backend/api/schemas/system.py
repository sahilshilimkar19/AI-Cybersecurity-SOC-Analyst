"""Contracts describing what the signed-in caller is permitted to do.

The client asks the server what this role may do rather than deciding from a
hard-coded role list. Two reasons. The RBAC table is the authority (SAD §14), and
a second copy of it in TypeScript is a copy that will drift. And a UI that offers
an action the backend will refuse teaches analysts to distrust the interface,
which is corrosive on a screen whose whole job is to make approval deliberate.

Hiding a control is a usability decision, never a security one: the capability
check runs on every request regardless of what the client rendered.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.enums import UserRole


class CapabilitiesResponse(BaseModel):
    """The caller's role and the capabilities it grants."""

    role: UserRole
    capabilities: list[str] = Field(default_factory=list)

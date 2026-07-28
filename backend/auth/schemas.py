"""Auth-layer models: the authenticated principal, federated identity, and the
request/response DTOs for the auth endpoints.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from models.enums import UserRole


class Principal(BaseModel):
    """The authenticated caller, derived from a verified access token."""

    user_id: UUID
    sso_subject: str
    email: str
    name: str
    role: UserRole
    session_id: str


class OidcIdentity(BaseModel):
    """Identity extracted from a validated OIDC ID token."""

    subject: str
    email: str
    name: str
    roles: list[str] = Field(default_factory=list)


class LoginInitResponse(BaseModel):
    """Response for the login initiation endpoint."""

    authorization_url: str
    state: str


class TokenResponse(BaseModel):
    """Access + refresh token pair returned after login or refresh."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str


class RefreshRequest(BaseModel):
    """Request body carrying a refresh token to rotate."""

    refresh_token: str


class MeResponse(BaseModel):
    """The current principal's profile."""

    id: UUID
    email: str
    name: str
    role: UserRole

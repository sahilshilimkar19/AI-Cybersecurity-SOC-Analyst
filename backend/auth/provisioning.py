"""Provision platform users from a validated OIDC identity."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.auth.schemas import OidcIdentity
from backend.db.orm.user import User
from backend.db.repositories.user import UserRepository
from models.enums import UserRole


def map_role(roles: list[str], default: UserRole) -> UserRole:
    """Map IdP role claims to a platform role, falling back to ``default``."""
    for raw in roles:
        try:
            return UserRole(raw)
        except ValueError:
            continue
    return default


def provision_user(session: Session, identity: OidcIdentity, *, default_role: UserRole) -> User:
    """Create or update the platform user for a federated identity."""
    role = map_role(identity.roles, default_role)
    repository = UserRepository(session)
    return repository.upsert_from_identity(
        sso_subject=identity.subject,
        email=identity.email,
        name=identity.name,
        role=role,
    )

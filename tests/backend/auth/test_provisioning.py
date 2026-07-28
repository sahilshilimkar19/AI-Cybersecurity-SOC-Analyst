"""Database tests for user provisioning from OIDC identities."""

from sqlalchemy.orm import Session

from backend.auth.provisioning import map_role, provision_user
from backend.auth.schemas import OidcIdentity
from models.enums import UserRole


def test_map_role_prefers_known_role() -> None:
    assert map_role(["unknown", "manager"], UserRole.ANALYST) is UserRole.MANAGER


def test_map_role_falls_back_to_default() -> None:
    assert map_role(["unknown"], UserRole.ANALYST) is UserRole.ANALYST
    assert map_role([], UserRole.AUDITOR) is UserRole.AUDITOR


def test_provision_creates_then_updates(db_session: Session) -> None:
    identity = OidcIdentity(
        subject="oidc|42",
        email="analyst@example.com",
        name="First Name",
        roles=["analyst"],
    )

    created = provision_user(db_session, identity, default_role=UserRole.ANALYST)
    created_id = created.id

    assert created.email == "analyst@example.com"
    assert created.role is UserRole.ANALYST

    # Second login with an updated profile + elevated role updates the same user.
    updated_identity = OidcIdentity(
        subject="oidc|42",
        email="analyst2@example.com",
        name="New Name",
        roles=["manager"],
    )
    updated = provision_user(db_session, updated_identity, default_role=UserRole.ANALYST)

    assert updated.id == created_id  # same user, not a duplicate
    assert updated.email == "analyst2@example.com"
    assert updated.name == "New Name"
    assert updated.role is UserRole.MANAGER

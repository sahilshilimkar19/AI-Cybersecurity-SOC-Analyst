"""User repository — lookups and provisioning from federated identity."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.orm.user import User
from backend.db.repositories.base import Repository
from models.enums import UserRole, UserStatus


class UserRepository(Repository[User]):
    """Data access for users, including OIDC-driven provisioning."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, User)

    def get_by_sso_subject(self, sso_subject: str) -> User | None:
        """Return the user federated to ``sso_subject``, or ``None``."""
        stmt = select(User).where(User.sso_subject == sso_subject)
        return self._session.execute(stmt).scalar_one_or_none()

    def upsert_from_identity(
        self, *, sso_subject: str, email: str, name: str, role: UserRole
    ) -> User:
        """Create or update the user for a federated identity.

        The IdP is the source of truth for profile and role, so email, name, and
        role are refreshed on each login.
        """
        user = self.get_by_sso_subject(sso_subject)
        if user is None:
            user = User(
                sso_subject=sso_subject,
                email=email,
                name=name,
                role=role,
                status=UserStatus.ACTIVE,
            )
            return self.add(user)
        user.email = email
        user.name = name
        user.role = role
        self._session.flush()
        return user

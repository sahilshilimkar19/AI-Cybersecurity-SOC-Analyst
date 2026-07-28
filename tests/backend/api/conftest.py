"""Fixtures for API endpoint tests.

Builds the app with test settings and overrides the OIDC client (a deterministic
stub, so no live IdP is needed) and the database dependency (bound to the test
engine). Database-backed tests truncate all tables afterward for isolation.
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

import backend.db  # noqa: F401 - registers ORM tables on Base.metadata
from backend.api.deps import get_db, get_oidc_client
from backend.app import create_app
from backend.auth.schemas import OidcIdentity
from backend.db.base import Base
from config.settings import Settings


class StubOidcClient:
    """Deterministic OIDC client for endpoint tests (no network / no IdP)."""

    def __init__(self, identity: OidcIdentity) -> None:
        self.identity = identity

    def build_authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        return f"https://idp.test/authorize?state={state}&nonce={nonce}&cc={code_challenge}"

    def exchange_code(self, *, code: str, code_verifier: str) -> str:
        return "stub-id-token"

    def validate_id_token(self, *, id_token: str, nonce: str) -> OidcIdentity:
        return self.identity


def _test_settings() -> Settings:
    return Settings(
        rate_limit_requests=1_000_000,
        session_backend="memory",
        log_json=False,
        log_level="WARNING",
        oidc_default_role="analyst",
    )


@pytest.fixture
def stub_identity() -> OidcIdentity:
    return OidcIdentity(
        subject="oidc|analyst",
        email="analyst@example.com",
        name="Test Analyst",
        roles=["analyst"],
    )


@pytest.fixture
def app_client(stub_identity: OidcIdentity) -> Iterator[TestClient]:
    """Client for endpoints that do not touch the database."""
    app = create_app(_test_settings())
    app.dependency_overrides[get_oidc_client] = lambda: StubOidcClient(stub_identity)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def client(db_engine: Engine, stub_identity: OidcIdentity) -> Iterator[TestClient]:
    """Client wired to the test database (and stub OIDC)."""
    app = create_app(_test_settings())
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_oidc_client] = lambda: StubOidcClient(stub_identity)
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client

    with db_engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())

"""Fixtures for API endpoint tests.

Builds the app with test settings and overrides the OIDC client (a deterministic
stub, so no live IdP is needed) and the database dependency (bound to the test
engine). Database-backed tests truncate all tables afterward for isolation.

The graph runtime is overridden with the **real** compiled graph over an
in-memory checkpointer rather than with a stub. The investigation endpoints are
worth testing against the pipeline they will actually run: a stub would agree
with whatever the routes expect, which is precisely the agreement that needs
checking.
"""

from collections.abc import Callable, Iterator
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

import backend.db  # noqa: F401 - registers ORM tables on Base.metadata
from backend.api.deps import get_db, get_db_session_factory, get_graph_runtime, get_oidc_client
from backend.app import create_app
from backend.auth.schemas import OidcIdentity, Principal
from backend.auth.tokens import TokenService
from backend.db.base import Base
from backend.db.orm.user import User
from config.settings import Settings
from graph.builder import build_investigation_graph
from graph.runtime import InvestigationGraphService
from models.enums import UserRole


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
    # Background runs and the event stream outlive the request that started them,
    # so they own their own sessions; both are pointed at the test engine.
    app.dependency_overrides[get_db_session_factory] = lambda: factory
    # One runtime for the whole client, mirroring the app-state caching the real
    # dependency does. A fresh one per request would carry a fresh checkpoint
    # store, and an investigation would be unresumable by the very next call.
    runtime = InvestigationGraphService(build_investigation_graph(checkpointer=InMemorySaver()))
    app.dependency_overrides[get_graph_runtime] = lambda: runtime
    with TestClient(app) as test_client:
        yield test_client

    with db_engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())


@pytest.fixture
def authenticate(db_engine: Engine) -> Callable[..., dict[str, str]]:
    """Mint an access token for a role, provisioning the user it names.

    Bypasses the OIDC dance deliberately: what these tests exercise is what a
    *role* may do, and routing every case through a login flow would test the
    login flow repeatedly instead.
    """
    settings = _test_settings()
    tokens = TokenService(
        secret=settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
        issuer=settings.jwt_issuer,
        access_ttl_seconds=settings.access_token_ttl_seconds,
    )
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)

    def _authenticate(
        role: UserRole = UserRole.ANALYST, *, user_id: UUID | None = None
    ) -> dict[str, str]:
        identifier = user_id or uuid4()
        session = factory()
        try:
            session.add(
                User(
                    id=identifier,
                    email=f"{role.value}-{identifier.hex[:8]}@example.com",
                    name=f"Test {role.value}",
                    role=role,
                    sso_subject=f"oidc|{identifier}",
                )
            )
            session.commit()
        finally:
            session.close()

        principal = Principal(
            user_id=identifier,
            sso_subject=f"oidc|{identifier}",
            email=f"{role.value}@example.com",
            name=f"Test {role.value}",
            role=role,
            session_id=f"sid-{identifier.hex[:8]}",
        )
        token, _ = tokens.issue_access_token(principal)
        return {"Authorization": f"Bearer {token}"}

    return _authenticate

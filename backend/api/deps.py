"""FastAPI dependency providers.

Wires settings, database sessions, the session store, the token/session services,
the OIDC client, and the authenticated principal. Providers read runtime services
from ``app.state`` (populated on startup) so tests can override them cleanly.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from uuid import UUID

import httpx
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from backend.auth.errors import AuthorizationError, InvalidTokenError
from backend.auth.oidc import JwksSigningKeyResolver, OidcClient, OidcProviderMetadata
from backend.auth.rbac import Capability, has_capability
from backend.auth.schemas import Principal
from backend.auth.sessions import SessionService, SessionStore
from backend.auth.tokens import TokenService
from backend.db.session import get_session_factory
from config.settings import Settings
from graph.runtime import InvestigationGraphService, build_graph_runtime
from integrations.notifications import NotificationChannelAdapter, build_channels
from models.enums import NotificationChannel


def get_settings_dep(request: Request) -> Settings:
    """Return the settings bound to the running app."""
    settings: Settings = request.app.state.settings
    return settings


def get_db() -> Iterator[Session]:
    """Yield a request-scoped database session (commit on success, else rollback)."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_session_factory(request: Request) -> Callable[[], Session]:
    """Return a factory for sessions outside the request scope.

    Background runs and the event stream both outlive the request that started
    them, so they cannot borrow the request-scoped session — it is closed the
    moment the response is returned. They get a factory and own their own
    transactions instead.
    """
    factory: Callable[[], Session] | None = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory()
        request.app.state.session_factory = factory
    return factory


def get_notification_channels(
    request: Request, settings: Settings = Depends(get_settings_dep)
) -> dict[NotificationChannel, NotificationChannelAdapter]:
    """Return the process's notification adapters, composing them on first use.

    Cached on ``app.state`` because each adapter owns a rate limiter and a
    circuit breaker, and those are only meaningful if they persist across
    requests — a breaker rebuilt per request is a breaker that never trips.
    """
    channels: dict[NotificationChannel, NotificationChannelAdapter] | None = getattr(
        request.app.state, "notification_channels", None
    )
    if channels is None:
        channels = build_channels(settings)
        request.app.state.notification_channels = channels
    return channels


def get_graph_runtime(request: Request) -> InvestigationGraphService:
    """Return the process's graph runtime, composing it on first use.

    Cached on ``app.state`` because the runtime owns the checkpointer, and a new
    one per request would give each request its own in-memory checkpoint store —
    an investigation would then be unresumable by the very next call.
    """
    runtime: InvestigationGraphService | None = getattr(request.app.state, "graph_runtime", None)
    if runtime is None:
        runtime = build_graph_runtime(request.app.state.settings)
        request.app.state.graph_runtime = runtime
    return runtime


def get_session_store(request: Request) -> SessionStore:
    store: SessionStore = request.app.state.session_store
    return store


def get_token_service(settings: Settings = Depends(get_settings_dep)) -> TokenService:
    return TokenService(
        secret=settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
        issuer=settings.jwt_issuer,
        access_ttl_seconds=settings.access_token_ttl_seconds,
    )


def get_session_service(
    store: SessionStore = Depends(get_session_store),
    settings: Settings = Depends(get_settings_dep),
) -> SessionService:
    return SessionService(store, refresh_ttl_seconds=settings.refresh_token_ttl_seconds)


def build_oidc_client(settings: Settings) -> OidcClient:
    """Construct an OIDC client via provider discovery (used in real deployments)."""
    if not settings.oidc_issuer:
        raise AuthorizationError("OIDC is not configured")
    discovery_url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    document = httpx.get(discovery_url, timeout=10.0).raise_for_status().json()
    metadata = OidcProviderMetadata.model_validate(document)
    return OidcClient(
        metadata=metadata,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        redirect_uri=settings.oidc_redirect_uri,
        scopes=settings.oidc_scopes,
        audience=settings.effective_oidc_audience,
        role_claim=settings.oidc_role_claim,
        key_resolver=JwksSigningKeyResolver(metadata.jwks_uri),
    )


def get_oidc_client(request: Request, settings: Settings = Depends(get_settings_dep)) -> OidcClient:
    """Return a cached OIDC client, building it on first use."""
    client = getattr(request.app.state, "oidc_client", None)
    if client is None:
        client = build_oidc_client(settings)
        request.app.state.oidc_client = client
    return client


def get_current_principal(
    request: Request, token_service: TokenService = Depends(get_token_service)
) -> Principal:
    """Authenticate the caller from the ``Authorization: Bearer`` header."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise InvalidTokenError("missing bearer token")
    claims = token_service.verify_access_token(token)
    return Principal(
        user_id=UUID(claims.sub),
        sso_subject=claims.sso_subject,
        email=claims.email,
        name=claims.name,
        role=claims.role,
        session_id=claims.sid,
    )


def require_capability(capability: Capability) -> Callable[[Principal], Principal]:
    """Build a dependency that requires the principal to hold ``capability``."""

    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not has_capability(principal.role, capability):
            raise AuthorizationError()
        return principal

    return dependency

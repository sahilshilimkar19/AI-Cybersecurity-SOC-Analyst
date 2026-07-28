"""Authentication endpoints (OIDC login, callback, refresh, logout, profile)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from backend.api.deps import (
    get_current_principal,
    get_db,
    get_oidc_client,
    get_session_service,
    get_session_store,
    get_settings_dep,
    get_token_service,
)
from backend.auth.errors import InvalidTokenError, OidcError
from backend.auth.oidc import (
    OidcClient,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
)
from backend.auth.provisioning import provision_user
from backend.auth.schemas import (
    LoginInitResponse,
    MeResponse,
    Principal,
    RefreshRequest,
    TokenResponse,
)
from backend.auth.sessions import LoginTransaction, SessionService, SessionStore
from backend.auth.tokens import TokenService
from backend.db.repositories.audit import AuditLogRepository
from backend.db.repositories.user import UserRepository
from config.settings import Settings
from models.enums import UserRole

router = APIRouter(prefix="/auth", tags=["auth"])

_LOGIN_TX_TTL_SECONDS = 600


@router.get("/login", response_model=LoginInitResponse)
def login(
    oidc: OidcClient = Depends(get_oidc_client),
    store: SessionStore = Depends(get_session_store),
) -> LoginInitResponse:
    """Begin OIDC login: return the IdP authorization URL and opaque state."""
    state = generate_state()
    nonce = generate_nonce()
    verifier, challenge = generate_pkce_pair()
    store.save_login(
        LoginTransaction(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            expires_at=datetime.now(UTC) + timedelta(seconds=_LOGIN_TX_TTL_SECONDS),
        )
    )
    url = oidc.build_authorization_url(state=state, nonce=nonce, code_challenge=challenge)
    return LoginInitResponse(authorization_url=url, state=state)


@router.get("/callback", response_model=TokenResponse)
def callback(
    code: str,
    state: str,
    oidc: OidcClient = Depends(get_oidc_client),
    store: SessionStore = Depends(get_session_store),
    db: Session = Depends(get_db),
    token_service: TokenService = Depends(get_token_service),
    session_service: SessionService = Depends(get_session_service),
    settings: Settings = Depends(get_settings_dep),
) -> TokenResponse:
    """Complete OIDC login: validate the IdP response, provision, and issue tokens."""
    transaction = store.pop_login(state)
    if transaction is None or transaction.expires_at <= datetime.now(UTC):
        raise OidcError("invalid or expired login state")

    id_token = oidc.exchange_code(code=code, code_verifier=transaction.code_verifier)
    identity = oidc.validate_id_token(id_token=id_token, nonce=transaction.nonce)

    user = provision_user(db, identity, default_role=UserRole(settings.oidc_default_role))
    session, refresh_token = session_service.start_session(user.id)
    principal = Principal(
        user_id=user.id,
        sso_subject=user.sso_subject or identity.subject,
        email=user.email,
        name=user.name,
        role=user.role,
        session_id=session.session_id,
    )
    access_token, expires_in = token_service.issue_access_token(principal)
    AuditLogRepository(db).append(
        action="auth.login", entity_type="user", entity_id=user.id, actor_id=user.id
    )
    return TokenResponse(
        access_token=access_token, expires_in=expires_in, refresh_token=refresh_token
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    body: RefreshRequest,
    db: Session = Depends(get_db),
    token_service: TokenService = Depends(get_token_service),
    session_service: SessionService = Depends(get_session_service),
) -> TokenResponse:
    """Rotate a refresh token and issue a new access token."""
    session, new_refresh_token = session_service.rotate(body.refresh_token)
    user = UserRepository(db).get(session.user_id)
    if user is None:
        raise InvalidTokenError("user not found for session")
    principal = Principal(
        user_id=user.id,
        sso_subject=user.sso_subject or "",
        email=user.email,
        name=user.name,
        role=user.role,
        session_id=session.session_id,
    )
    access_token, expires_in = token_service.issue_access_token(principal)
    return TokenResponse(
        access_token=access_token, expires_in=expires_in, refresh_token=new_refresh_token
    )


@router.post("/logout", status_code=204)
def logout(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    session_service: SessionService = Depends(get_session_service),
) -> Response:
    """Revoke the current session (and its refresh tokens)."""
    session_service.revoke(principal.session_id)
    AuditLogRepository(db).append(
        action="auth.logout",
        entity_type="user",
        entity_id=principal.user_id,
        actor_id=principal.user_id,
    )
    return Response(status_code=204)


@router.get("/me", response_model=MeResponse)
def me(principal: Principal = Depends(get_current_principal)) -> MeResponse:
    """Return the current principal's profile."""
    return MeResponse(
        id=principal.user_id,
        email=principal.email,
        name=principal.name,
        role=principal.role,
    )

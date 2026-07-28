"""Tests for the access-token service."""

from uuid import uuid4

import jwt
import pytest

from backend.auth.errors import InvalidTokenError, TokenExpiredError
from backend.auth.schemas import Principal
from backend.auth.tokens import TokenService
from models.enums import UserRole


def _principal() -> Principal:
    return Principal(
        user_id=uuid4(),
        sso_subject="oidc|123",
        email="analyst@example.com",
        name="Test Analyst",
        role=UserRole.ANALYST,
        session_id="sess-1",
    )


def _service(ttl: int = 900) -> TokenService:
    return TokenService(
        secret="test-secret", algorithm="HS256", issuer="soc-analyst", access_ttl_seconds=ttl
    )


def test_issue_and_verify_round_trip() -> None:
    service = _service()
    principal = _principal()

    token, expires_in = service.issue_access_token(principal)
    claims = service.verify_access_token(token)

    assert expires_in == 900
    assert claims.sub == str(principal.user_id)
    assert claims.sid == "sess-1"
    assert claims.role is UserRole.ANALYST
    assert claims.email == "analyst@example.com"
    assert claims.name == "Test Analyst"


def test_expired_token_is_rejected() -> None:
    service = _service(ttl=-1)  # already expired
    token, _ = service.issue_access_token(_principal())

    with pytest.raises(TokenExpiredError):
        service.verify_access_token(token)


def test_tampered_token_is_rejected() -> None:
    token, _ = _service().issue_access_token(_principal())

    with pytest.raises(InvalidTokenError):
        _service().verify_access_token(token + "tampered")


def test_wrong_issuer_is_rejected() -> None:
    token, _ = _service().issue_access_token(_principal())
    other = TokenService(
        secret="test-secret", algorithm="HS256", issuer="someone-else", access_ttl_seconds=900
    )

    with pytest.raises(InvalidTokenError):
        other.verify_access_token(token)


def test_wrong_secret_is_rejected() -> None:
    token, _ = _service().issue_access_token(_principal())
    forged = TokenService(
        secret="other-secret", algorithm="HS256", issuer="soc-analyst", access_ttl_seconds=900
    )

    with pytest.raises(InvalidTokenError):
        forged.verify_access_token(token)


def test_missing_required_claim_is_rejected() -> None:
    # A token without the required "exp" claim must be rejected.
    token = jwt.encode(
        {"sub": "x", "iss": "soc-analyst", "iat": 0}, "test-secret", algorithm="HS256"
    )

    with pytest.raises(InvalidTokenError):
        _service().verify_access_token(token)

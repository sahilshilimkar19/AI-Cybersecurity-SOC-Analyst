"""Tests for the OIDC client (offline, using a locally-generated signing key)."""

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.auth.errors import OidcError
from backend.auth.oidc import (
    OidcClient,
    OidcProviderMetadata,
    generate_pkce_pair,
)

_ISSUER = "https://idp.test"
_CLIENT_ID = "soc-client"

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_private_pem = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


class _StaticKeyResolver:
    def __init__(self, key: Any) -> None:
        self._key = key

    def resolve(self, token: str) -> Any:
        return self._key


def _metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=_ISSUER,
        authorization_endpoint=f"{_ISSUER}/authorize",
        token_endpoint=f"{_ISSUER}/token",
        jwks_uri=f"{_ISSUER}/jwks",
    )


def _client(http_client: httpx.Client | None = None) -> OidcClient:
    return OidcClient(
        metadata=_metadata(),
        client_id=_CLIENT_ID,
        client_secret="secret",
        redirect_uri="http://localhost:8000/auth/callback",
        scopes="openid profile email",
        audience=_CLIENT_ID,
        role_claim="roles",
        key_resolver=_StaticKeyResolver(_private_key.public_key()),
        http_client=http_client,
    )


def _id_token(**overrides: Any) -> str:
    now = int(datetime.now(UTC).timestamp())
    claims: dict[str, Any] = {
        "sub": "oidc|1",
        "email": "analyst@example.com",
        "name": "Test Analyst",
        "roles": ["analyst"],
        "aud": _CLIENT_ID,
        "iss": _ISSUER,
        "iat": now,
        "exp": now + 300,
        "nonce": "nonce-1",
    }
    claims.update(overrides)
    return jwt.encode(claims, _private_pem, algorithm="RS256")


def test_build_authorization_url_contains_pkce_and_state() -> None:
    url = _client().build_authorization_url(state="st", nonce="no", code_challenge="ch")
    assert url.startswith(f"{_ISSUER}/authorize?")
    assert "client_id=soc-client" in url
    assert "code_challenge_method=S256" in url
    assert "state=st" in url


def test_generate_pkce_pair_is_urlsafe_without_padding() -> None:
    verifier, challenge = generate_pkce_pair()
    assert verifier and challenge
    assert "=" not in challenge


def test_validate_id_token_success() -> None:
    identity = _client().validate_id_token(id_token=_id_token(), nonce="nonce-1")
    assert identity.subject == "oidc|1"
    assert identity.email == "analyst@example.com"
    assert identity.roles == ["analyst"]


def test_validate_rejects_nonce_mismatch() -> None:
    with pytest.raises(OidcError):
        _client().validate_id_token(id_token=_id_token(), nonce="wrong-nonce")


def test_validate_rejects_wrong_audience() -> None:
    with pytest.raises(OidcError):
        _client().validate_id_token(id_token=_id_token(aud="other-client"), nonce="nonce-1")


def test_validate_rejects_expired_token() -> None:
    past = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp())
    with pytest.raises(OidcError):
        _client().validate_id_token(id_token=_id_token(exp=past), nonce="nonce-1")


def test_exchange_code_returns_id_token() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id_token": "the-id-token", "access_token": "a"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = _client(http_client=http_client)
        assert client.exchange_code(code="code", code_verifier="verifier") == "the-id-token"


def test_exchange_code_raises_on_error_status() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = _client(http_client=http_client)
        with pytest.raises(OidcError):
            client.exchange_code(code="bad", code_verifier="verifier")

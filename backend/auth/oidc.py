"""OIDC Relying Party client.

Implements the authorization-code flow with PKCE: build the authorization URL,
exchange the code for tokens, and validate the ID token's signature (via the
provider's JWKS) and claims. Signing-key resolution is behind an interface so
validation can be tested offline with a local key.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient
from pydantic import BaseModel

from backend.auth.errors import OidcError
from backend.auth.schemas import OidcIdentity


class OidcProviderMetadata(BaseModel):
    """The subset of OIDC discovery metadata the client needs."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


class SigningKeyResolver(Protocol):
    """Resolves the verification key for a signed JWT."""

    def resolve(self, token: str) -> Any: ...


class JwksSigningKeyResolver:
    """Resolves signing keys from the provider's JWKS endpoint."""

    def __init__(self, jwks_uri: str) -> None:
        self._client = PyJWKClient(jwks_uri)

    def resolve(self, token: str) -> Any:
        return self._client.get_signing_key_from_jwt(token).key


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    return secrets.token_urlsafe(32)


def generate_pkce_pair() -> tuple[str, str]:
    """Return a (code_verifier, code_challenge) PKCE pair (S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class OidcClient:
    """OIDC Relying Party operations against a configured provider."""

    def __init__(
        self,
        *,
        metadata: OidcProviderMetadata,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: str,
        audience: str,
        role_claim: str,
        key_resolver: SigningKeyResolver,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._metadata = metadata
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._audience = audience or client_id
        self._role_claim = role_claim
        self._key_resolver = key_resolver
        self._http_client = http_client

    def build_authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        """Build the IdP authorization URL for the code flow with PKCE."""
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": self._scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self._metadata.authorization_endpoint}?{urlencode(params)}"

    def exchange_code(self, *, code: str, code_verifier: str) -> str:
        """Exchange an authorization code for tokens; return the ID token."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code_verifier": code_verifier,
        }
        owns_client = self._http_client is None
        client = self._http_client or httpx.Client(timeout=10.0)
        try:
            response = client.post(self._metadata.token_endpoint, data=data)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            raise OidcError("token endpoint request failed") from exc
        finally:
            if owns_client:
                client.close()
        id_token = body.get("id_token")
        if not id_token:
            raise OidcError("token response did not contain an id_token")
        return str(id_token)

    def validate_id_token(self, *, id_token: str, nonce: str) -> OidcIdentity:
        """Validate an ID token's signature and claims, returning the identity."""
        try:
            key = self._key_resolver.resolve(id_token)
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._metadata.issuer,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("invalid id token") from exc
        if claims.get("nonce") != nonce:
            raise OidcError("id token nonce mismatch")
        raw_roles = claims.get(self._role_claim, [])
        roles = raw_roles if isinstance(raw_roles, list) else [raw_roles]
        return OidcIdentity(
            subject=str(claims["sub"]),
            email=str(claims.get("email", "")),
            name=str(claims.get("name", "")),
            roles=[str(role) for role in roles],
        )

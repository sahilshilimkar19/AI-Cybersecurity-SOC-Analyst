"""Access-token service.

Issues and verifies the platform's own short-lived access tokens (signed JWTs).
These are distinct from the external IdP's tokens: after OIDC login the platform
mints its own access token bound to a server-side session.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from pydantic import BaseModel

from backend.auth.errors import InvalidTokenError, TokenExpiredError
from backend.auth.schemas import Principal
from models.enums import UserRole


class AccessTokenClaims(BaseModel):
    """Validated claims carried by an access token."""

    sub: str
    sid: str
    role: UserRole
    email: str
    name: str
    sso_subject: str
    iss: str
    iat: int
    exp: int
    typ: str = "access"


class TokenService:
    """Signs and verifies access tokens with a symmetric secret."""

    def __init__(
        self, *, secret: str, algorithm: str, issuer: str, access_ttl_seconds: int
    ) -> None:
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._ttl = access_ttl_seconds

    def issue_access_token(self, principal: Principal) -> tuple[str, int]:
        """Return a signed access token and its lifetime in seconds."""
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=self._ttl)
        claims = {
            "sub": str(principal.user_id),
            "sid": principal.session_id,
            "role": principal.role.value,
            "email": principal.email,
            "name": principal.name,
            "sso_subject": principal.sso_subject,
            "iss": self._issuer,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "typ": "access",
        }
        token = jwt.encode(claims, self._secret, algorithm=self._algorithm)
        return token, self._ttl

    def verify_access_token(self, token: str) -> AccessTokenClaims:
        """Verify a token's signature and claims, returning them."""
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("access token expired") from exc
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("invalid access token") from exc
        return AccessTokenClaims.model_validate(payload)

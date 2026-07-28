"""Authentication and authorization errors.

Each error carries an HTTP ``status_code`` and a stable machine-readable
``error`` code; the API layer renders them as JSON without leaking internals.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base authentication error (HTTP 401)."""

    status_code: int = 401
    error: str = "authentication_error"

    def __init__(self, message: str = "authentication failed") -> None:
        super().__init__(message)
        self.message = message


class InvalidTokenError(AuthError):
    """A token was missing, malformed, or failed verification."""

    error = "invalid_token"


class TokenExpiredError(AuthError):
    """A token was well-formed but expired."""

    error = "token_expired"


class RefreshReuseError(AuthError):
    """A refresh token was replayed after rotation — the session is revoked."""

    error = "refresh_token_reuse"


class OidcError(AuthError):
    """An error occurred during the OIDC login exchange or validation."""

    error = "oidc_error"


class AuthorizationError(AuthError):
    """The principal is authenticated but lacks the required permission (HTTP 403)."""

    status_code = 403
    error = "forbidden"

    def __init__(self, message: str = "insufficient permissions") -> None:
        super().__init__(message)

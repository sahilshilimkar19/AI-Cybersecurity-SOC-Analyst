"""API error taxonomy and exception handlers.

Errors carry a stable machine-readable code and a status, and are rendered as
JSON without leaking internals — the same contract the auth errors established
(EDS §11 typed error taxonomy).

Graph errors are translated here rather than at the call sites. Whether a resume
was refused because no gate was open is an HTTP concern exactly once, and a
handler is the one place where that mapping cannot be forgotten on a new route.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.requests import Request

from backend.auth.errors import AuthError
from graph.errors import InvalidResumeError, InvestigationNotFoundError


class ApiError(Exception):
    """Base API error carrying an HTTP status and a stable error code."""

    status_code: int = 400
    error: str = "bad_request"

    def __init__(self, message: str = "the request could not be processed") -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(ApiError):
    """The addressed resource does not exist, or is not visible to the caller."""

    status_code = 404
    error = "not_found"

    def __init__(self, message: str = "resource not found") -> None:
        super().__init__(message)


class ConflictError(ApiError):
    """The request is valid but conflicts with the resource's current state.

    Used where an operation would otherwise overwrite a record of what a person
    decided — re-deciding an approval, resuming an investigation that is not
    paused. Failing loudly is the point: a silently accepted duplicate makes the
    audit trail describe something that did not happen.
    """

    status_code = 409
    error = "conflict"

    def __init__(self, message: str = "conflicting request") -> None:
        super().__init__(message)


async def _auth_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AuthError)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "message": exc.message},
    )


async def _api_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ApiError)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "message": exc.message},
    )


async def _investigation_missing_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"error": "not_found", "message": "no such investigation"},
    )


async def _invalid_resume_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={"error": "conflict", "message": str(exc)},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register application exception handlers on ``app``."""
    app.add_exception_handler(AuthError, _auth_error_handler)
    app.add_exception_handler(ApiError, _api_error_handler)
    app.add_exception_handler(InvestigationNotFoundError, _investigation_missing_handler)
    app.add_exception_handler(InvalidResumeError, _invalid_resume_handler)

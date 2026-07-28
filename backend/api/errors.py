"""API exception handlers.

Maps domain auth errors to JSON responses with the correct status code, without
leaking internal detail.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.requests import Request

from backend.auth.errors import AuthError


async def _auth_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AuthError)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "message": exc.message},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register application exception handlers on ``app``."""
    app.add_exception_handler(AuthError, _auth_error_handler)

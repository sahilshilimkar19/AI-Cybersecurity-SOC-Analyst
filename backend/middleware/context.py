"""Request-context middleware.

Assigns a correlation id to every request, binds it (plus method and path) to the
structured-logging context, echoes it back as ``X-Request-ID``, and logs a
completion event. This is the backbone of request tracing (EDS §13).
"""

from __future__ import annotations

import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from config.logging import get_logger

_REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind a request id and structured logging context for each request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get(_REQUEST_ID_HEADER) or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        try:
            response = await call_next(request)
            response.headers[_REQUEST_ID_HEADER] = request_id
            get_logger("http").info("request_completed", status_code=response.status_code)
            return response
        finally:
            structlog.contextvars.clear_contextvars()

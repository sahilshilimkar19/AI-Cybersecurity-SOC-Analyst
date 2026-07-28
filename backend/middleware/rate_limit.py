"""Fixed-window rate-limiting middleware.

A lightweight per-client, per-process limiter that protects against bursts and
abusive clients (SAD §14). It is intentionally simple; distributed rate limiting
(shared across replicas) is a later hardening concern.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Reject a client that exceeds ``max_requests`` within ``window_seconds``."""

    def __init__(self, app: ASGIApp, *, max_requests: int, window_seconds: int) -> None:
        super().__init__(app)
        self._max = max_requests
        self._window = window_seconds
        self._hits: dict[tuple[str, int], int] = {}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client = request.client.host if request.client else "unknown"
        bucket = int(time.time()) // self._window
        key = (client, bucket)
        count = self._hits.get(key, 0) + 1
        self._hits[key] = count
        if count == 1:
            self._evict_old_buckets(bucket)
        if count > self._max:
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "message": "too many requests"},
            )
        return await call_next(request)

    def _evict_old_buckets(self, current_bucket: int) -> None:
        stale = [key for key in self._hits if key[1] < current_bucket]
        for key in stale:
            self._hits.pop(key, None)

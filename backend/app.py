"""FastAPI application factory.

Assembles the API: middleware pipeline, exception handlers, routers, and the
runtime services (settings, session store) placed on ``app.state`` at startup.
Run with: ``uvicorn backend.app:create_app --factory``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI

from backend.api.errors import register_exception_handlers
from backend.api.routes import auth, health
from backend.auth.sessions import InMemorySessionStore, RedisSessionStore, SessionStore
from backend.middleware.context import RequestContextMiddleware
from backend.middleware.rate_limit import RateLimitMiddleware
from config.logging import configure_logging
from config.settings import Settings, get_settings


def build_session_store(settings: Settings) -> SessionStore:
    """Build the configured session store (in-memory or Redis)."""
    if settings.session_backend == "redis":
        return RedisSessionStore(redis.Redis.from_url(settings.redis_url))
    return InMemorySessionStore()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    resolved = settings or get_settings()
    configure_logging(resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = resolved
        app.state.session_store = build_session_store(resolved)
        app.state.oidc_client = None
        yield

    app = FastAPI(
        title="AI Cybersecurity SOC Analyst API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=resolved.rate_limit_requests,
        window_seconds=resolved.rate_limit_window_seconds,
    )
    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(auth.router)
    return app

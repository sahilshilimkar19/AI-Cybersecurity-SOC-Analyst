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
from fastapi.middleware.cors import CORSMiddleware

from backend.api.errors import register_exception_handlers
from backend.api.routes import auth, health, investigations, notifications, system
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
        # Composed lazily on first use so importing the app — in tests, in
        # migrations, in `--help` — does not open a checkpoint connection.
        app.state.graph_runtime = None
        app.state.session_factory = None
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
    # The SPA runs on its own origin and sends a bearer token, so the browser
    # requires an explicit origin allow-list — never a wildcard, which it refuses
    # for credentialed requests anyway. Methods and headers are enumerated rather
    # than opened up: this is the only cross-origin surface the platform has.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        # SSE reconnection reads the last delivered event id off the response.
        expose_headers=["Content-Type"],
    )
    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(system.router)
    app.include_router(investigations.router)
    app.include_router(notifications.router)
    return app

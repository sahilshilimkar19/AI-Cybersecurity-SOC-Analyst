"""Structured logging configuration for the platform.

Configures ``structlog`` to emit either JSON logs (for staging/production log
pipelines) or human-readable console logs (for local development), at the level
declared in :class:`~config.settings.Settings`.

Logs are structured key-value events. Engineers must never log secrets or PII and
must escape untrusted content (governing invariant #3; EDS §11, §13).
"""

from __future__ import annotations

import logging
from typing import cast

import structlog
from structlog.typing import FilteringBoundLogger, Processor

from config.settings import Settings


def configure_logging(settings: Settings) -> None:
    """Configure process-wide structured logging from ``settings``.

    Idempotent: safe to call once at process startup. The chosen renderer (JSON
    vs. console) and level are derived from the provided settings.
    """
    level: int = getattr(logging, settings.log_level.value)
    logging.basicConfig(format="%(message)s", level=level)

    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if settings.log_json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> FilteringBoundLogger:
    """Return a structured logger, optionally bound to ``name``.

    ``configure_logging`` should have been called once at startup; if it has not,
    structlog falls back to its default configuration.
    """
    return cast(FilteringBoundLogger, structlog.get_logger(name))

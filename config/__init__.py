"""Configuration layer — typed settings and structured logging foundation.

This is the only substantive code delivered in the Bootstrap sprint. It provides
the validated configuration and structured logging that every later layer builds
on. See docs/ENGINEERING_DESIGN_SPEC.md §3.14.
"""

from config.logging import configure_logging, get_logger
from config.settings import Environment, LogLevel, Settings, get_settings

__all__ = [
    "Environment",
    "LogLevel",
    "Settings",
    "configure_logging",
    "get_logger",
    "get_settings",
]

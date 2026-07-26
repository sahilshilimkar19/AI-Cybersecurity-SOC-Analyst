"""Application configuration foundation.

Typed, validated settings loaded from environment variables (prefixed ``SOC_``)
and an optional ``.env`` file. Configuration **fails fast** on invalid values so a
misconfigured process never starts, and is resolved once per process.

See docs/ENGINEERING_DESIGN_SPEC.md §3.14 (Configuration) and §11 (Coding Standards).
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment the process is running in."""

    LOCAL = "local"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    """Standard logging verbosity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """Process-wide application settings.

    Values are read (in precedence order) from constructor arguments, then
    ``SOC_``-prefixed environment variables, then a ``.env`` file, then the
    defaults below. Secrets are never defined here; they are resolved at runtime
    from the external secret store in the sprints that introduce them.
    """

    model_config = SettingsConfigDict(
        env_prefix="SOC_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = Field(
        default="AI Cybersecurity SOC Analyst",
        description="Human-readable application name.",
    )
    environment: Environment = Field(
        default=Environment.LOCAL,
        description="Deployment environment.",
    )
    debug: bool = Field(
        default=False,
        description="Debug mode. Must be false in production.",
    )
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging verbosity.",
    )
    log_json: bool = Field(
        default=True,
        description="Emit structured JSON logs (true) or console logs (false).",
    )

    @property
    def is_production(self) -> bool:
        """Whether the process is running in the production environment."""
        return self.environment is Environment.PRODUCTION

    @model_validator(mode="after")
    def _enforce_production_safety(self) -> Settings:
        """Fail fast on unsafe production configuration."""
        if self.is_production and self.debug:
            raise ValueError("SOC_DEBUG must be false in the production environment.")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so configuration is resolved and validated exactly once per process.
    Tests that mutate the environment should call ``get_settings.cache_clear()``.
    """
    return Settings()

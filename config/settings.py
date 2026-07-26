"""Application configuration foundation.

Typed, validated settings loaded from environment variables (prefixed ``SOC_``)
and an optional ``.env`` file. Configuration **fails fast** on invalid values so a
misconfigured process never starts, and is resolved once per process.

See docs/ENGINEERING_DESIGN_SPEC.md §3.14 (Configuration) and §11 (Coding Standards).
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
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

    # --- Database (Sprint 2) ------------------------------------------------
    # SQLAlchemy URL. The default targets the local docker-compose PostgreSQL
    # and is a LOCAL-ONLY convenience; production supplies this via the secret
    # store / environment.
    database_url: str = Field(
        default="postgresql+psycopg://soc:soc_local_pw@localhost:5432/soc_analyst",
        description="SQLAlchemy database URL.",
    )
    database_echo: bool = Field(
        default=False,
        description="Echo SQL statements (debugging only).",
    )
    database_pool_size: int = Field(
        default=5,
        ge=1,
        description="Connection pool size.",
    )

    # --- Object storage for raw evidence (Sprint 2) -------------------------
    # Defaults target the local docker-compose MinIO and are LOCAL-ONLY.
    object_store_endpoint: str = Field(
        default="localhost:9000",
        description="S3-compatible object-store endpoint (host:port).",
    )
    object_store_access_key: str = Field(
        default="soc_minio",
        description="Object-store access key.",
    )
    object_store_secret_key: SecretStr = Field(
        default=SecretStr("soc_minio_local_pw"),
        description="Object-store secret key.",
    )
    object_store_bucket: str = Field(
        default="soc-evidence",
        description="Bucket holding immutable raw log evidence.",
    )
    object_store_secure: bool = Field(
        default=False,
        description="Use TLS for the object store (true in production).",
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

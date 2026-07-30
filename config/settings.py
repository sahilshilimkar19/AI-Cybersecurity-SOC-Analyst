"""Application configuration foundation.

Typed, validated settings loaded from environment variables (prefixed ``SOC_``)
and an optional ``.env`` file. Configuration **fails fast** on invalid values so a
misconfigured process never starts, and is resolved once per process.

See docs/ENGINEERING_DESIGN_SPEC.md §3.14 (Configuration) and §11 (Coding Standards).
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Local-only default JWT secret; production is required to override it (validated below).
_INSECURE_JWT_SECRET = "dev-insecure-change-me"


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

    # --- OIDC (Sprint 3) ----------------------------------------------------
    # The platform is an OIDC Relying Party; identity is federated to an external
    # IdP. These are configured per environment (client secret via secret store).
    oidc_issuer: str = Field(default="", description="OIDC issuer URL.")
    oidc_client_id: str = Field(default="", description="OIDC client identifier.")
    oidc_client_secret: SecretStr = Field(default=SecretStr(""), description="OIDC client secret.")
    oidc_redirect_uri: str = Field(
        default="http://localhost:8000/auth/callback",
        description="Registered OIDC redirect/callback URI.",
    )
    oidc_scopes: str = Field(
        default="openid profile email", description="Space-separated OIDC scopes."
    )
    oidc_audience: str = Field(
        default="", description="Expected ID-token audience (defaults to client id)."
    )
    oidc_role_claim: str = Field(
        default="roles", description="ID-token claim carrying the user's roles."
    )
    oidc_default_role: str = Field(
        default="analyst", description="Role assigned when the token carries none."
    )

    # --- Session tokens (Sprint 3) ------------------------------------------
    # The RP issues its own short-lived access JWT plus a rotating refresh token.
    jwt_secret: SecretStr = Field(
        default=SecretStr(_INSECURE_JWT_SECRET),
        description="Secret used to sign the platform's access tokens.",
    )
    jwt_algorithm: str = Field(default="HS256", description="Access-token signing algorithm.")
    jwt_issuer: str = Field(default="soc-analyst", description="Access-token issuer claim.")
    access_token_ttl_seconds: int = Field(
        default=900, ge=60, description="Access-token lifetime (seconds)."
    )
    refresh_token_ttl_seconds: int = Field(
        default=604800, ge=300, description="Refresh-token lifetime (seconds)."
    )

    # --- Sessions & rate limiting (Sprint 3) --------------------------------
    session_backend: Literal["memory", "redis"] = Field(
        default="memory", description="Session/refresh store backend."
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0", description="Redis URL for the session store."
    )
    rate_limit_requests: int = Field(
        default=100, ge=1, description="Max requests per window per client."
    )
    rate_limit_window_seconds: int = Field(
        default=60, ge=1, description="Rate-limit window length (seconds)."
    )

    # --- Graph orchestration (Sprint 4) -------------------------------------
    # The deterministic control plane. Checkpoints are the unit of resume and
    # rollback; a durable Postgres backend is introduced with the durable memory
    # tier in the Memory sprint, so only "memory" is selectable today.
    graph_checkpoint_backend: Literal["memory"] = Field(
        default="memory", description="Graph checkpoint storage backend."
    )
    graph_max_retries: int = Field(
        default=3, ge=1, description="Maximum attempts (including the first) per retriable node."
    )
    graph_retry_initial_seconds: float = Field(
        default=0.5, gt=0, description="Initial backoff interval before the first node retry."
    )
    graph_retry_backoff_factor: float = Field(
        default=2.0, ge=1.0, description="Multiplier applied to the backoff interval each retry."
    )
    graph_retry_max_seconds: float = Field(
        default=30.0, gt=0, description="Maximum backoff interval between node retries."
    )

    @property
    def is_production(self) -> bool:
        """Whether the process is running in the production environment."""
        return self.environment is Environment.PRODUCTION

    @property
    def effective_oidc_audience(self) -> str:
        """The expected ID-token audience (defaults to the client id)."""
        return self.oidc_audience or self.oidc_client_id

    @model_validator(mode="after")
    def _enforce_production_safety(self) -> Settings:
        """Fail fast on unsafe production configuration."""
        if self.is_production and self.debug:
            raise ValueError("SOC_DEBUG must be false in the production environment.")
        if self.is_production and self.jwt_secret.get_secret_value() == _INSECURE_JWT_SECRET:
            raise ValueError("SOC_JWT_SECRET must be set to a strong value in production.")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so configuration is resolved and validated exactly once per process.
    Tests that mutate the environment should call ``get_settings.cache_clear()``.
    """
    return Settings()

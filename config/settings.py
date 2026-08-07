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

from models.enums import NotificationChannel, TriagePriority

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
    # rollback. The durable Postgres backend (Sprint 5) lets an investigation
    # survive a worker restart; "memory" is per-process and for tests/local use.
    graph_checkpoint_backend: Literal["memory", "postgres"] = Field(
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

    # --- Memory layer (Sprint 5) --------------------------------------------
    # Tiered memory (EDS §7). The hot tier is Redis in real deployments and
    # in-process for tests/local; the durable tier is always PostgreSQL and is
    # the source of truth on conflict.
    memory_hot_backend: Literal["memory", "redis"] = Field(
        default="memory", description="Hot (fast) memory tier backend."
    )
    memory_namespace: str = Field(
        default="soc:mem", description="Key namespace for the hot memory tier."
    )
    memory_session_ttl_seconds: int = Field(
        default=3600, ge=60, description="TTL for hot session-memory entries (seconds)."
    )
    memory_working_token_budget: int = Field(
        default=8000,
        ge=256,
        description="Token budget bounding working memory; overflow is summarized out.",
    )
    memory_working_max_entries: int = Field(
        default=200, ge=1, description="Maximum entries retained in working memory."
    )

    # --- RAG pipeline (Sprint 6) --------------------------------------------
    # Grounding and citations (EDS §8). The embedding model and dimensions are
    # pinned per index version: changing either requires re-embedding under a new
    # index version, never an in-place edit.
    embedding_provider: Literal["deterministic"] = Field(
        default="deterministic",
        description="Embedding provider backend (model-backed providers arrive with the AI layer).",
    )
    embedding_model: str = Field(
        default="deterministic-hash-v1", description="Embedding model identifier pinned per index."
    )
    rag_chunk_max_characters: int = Field(
        default=1200, ge=200, description="Maximum characters per chunk before splitting."
    )
    rag_chunk_overlap_characters: int = Field(
        default=120, ge=0, description="Overlap between split chunks, to preserve context."
    )
    rag_retrieval_top_k: int = Field(
        default=5, ge=1, description="Chunks returned per retrieval after ranking."
    )
    rag_retrieval_candidates: int = Field(
        default=50, ge=1, description="Candidates fetched per retrieval path before ranking."
    )
    rag_context_token_budget: int = Field(
        default=4000, ge=256, description="Token budget bounding retrieved context."
    )
    rag_freshness_half_life_days: float = Field(
        default=180.0, gt=0, description="Age at which a source's freshness weight halves."
    )
    rag_cache_ttl_seconds: int = Field(
        default=900, ge=0, description="TTL for cached retrieval results (0 disables caching)."
    )

    # --- Threat intelligence (Sprint 8) -------------------------------------
    # IoC reputation enrichment. The default is deliberately "none": an
    # unconfigured deployment produces assessments explicitly flagged as
    # enrichment-unavailable rather than ones that quietly assume indicators are
    # clean. The resilience knobs bound the blast radius of a slow or throttled
    # provider (EDS §3.12).
    threat_intel_provider: Literal["none", "virustotal"] = Field(
        default="none", description="IoC reputation provider; 'none' disables enrichment."
    )
    virustotal_api_key: SecretStr = Field(
        default=SecretStr(""), description="VirusTotal API key (resolved from the secret store)."
    )
    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3", description="VirusTotal API v3 base URL."
    )
    threat_intel_timeout_seconds: float = Field(
        default=5.0, gt=0, description="Per-request timeout for reputation lookups."
    )
    threat_intel_cache_ttl_seconds: int = Field(
        default=3600, ge=0, description="TTL for cached reputation verdicts (0 disables caching)."
    )
    threat_intel_rate_limit_per_minute: int = Field(
        default=4,
        ge=1,
        description="Reputation lookups permitted per minute (VirusTotal's free tier allows 4).",
    )
    threat_intel_breaker_failure_threshold: int = Field(
        default=3, ge=1, description="Consecutive failures before the intel circuit opens."
    )
    threat_intel_breaker_reset_seconds: float = Field(
        default=60.0, gt=0, description="How long the intel circuit stays open before probing."
    )
    threat_intel_max_indicators: int = Field(
        default=25,
        ge=1,
        description="Maximum indicators enriched per assessment, bounding cost and latency.",
    )

    # --- Threat detection (Sprint 8) ----------------------------------------
    threat_correlation_window_minutes: int = Field(
        default=30,
        ge=1,
        description="Window within which detection heuristics group related activity.",
    )

    # --- CVE research (Sprint 9) --------------------------------------------
    # The live vulnerability feed. NVD is reachable without an API key, but
    # whether this platform makes outbound calls at all is an operator decision:
    # with the source disabled the agent researches from the indexed corpus and
    # marks the dossier stale, which is the documented degraded path (EDS §4.4).
    cve_source: Literal["none", "nvd"] = Field(
        default="none", description="Live CVE feed; 'none' researches from the indexed corpus."
    )
    nvd_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD CVE API v2 endpoint.",
    )
    nvd_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="NVD API key (optional; raises the published rate limit).",
    )
    nvd_timeout_seconds: float = Field(
        default=10.0, gt=0, description="Per-request timeout for NVD lookups."
    )
    nvd_cache_ttl_seconds: int = Field(
        default=21600, ge=0, description="TTL for cached CVE records (0 disables caching)."
    )
    nvd_rate_limit_per_window: int = Field(
        default=5,
        ge=1,
        description="NVD requests permitted per window (5 without an API key, 50 with one).",
    )
    nvd_rate_limit_window_seconds: float = Field(
        default=30.0, gt=0, description="Length of the NVD rate-limit window (seconds)."
    )
    nvd_breaker_failure_threshold: int = Field(
        default=3, ge=1, description="Consecutive failures before the NVD circuit opens."
    )
    nvd_breaker_reset_seconds: float = Field(
        default=60.0, gt=0, description="How long the NVD circuit stays open before probing."
    )
    cve_max_products_searched: int = Field(
        default=12,
        ge=1,
        description="Maximum inventory products researched per investigation, bounding cost.",
    )
    cve_results_per_product: int = Field(
        default=10, ge=1, description="Maximum CVE records considered per product searched."
    )

    # --- Remediation advisories (Sprint 11) ---------------------------------
    # Fixed-version lookup. Without it a remediation plan still recommends
    # patching but cannot name the target release, which is the difference
    # between actionable and merely correct.
    advisory_source: Literal["none", "github"] = Field(
        default="none", description="Security advisory feed used to resolve fixed versions."
    )
    github_advisories_url: str = Field(
        default="https://api.github.com/advisories",
        description="GitHub Security Advisories API endpoint.",
    )
    github_token: SecretStr = Field(
        default=SecretStr(""),
        description="GitHub token (optional; raises the advisory API rate limit).",
    )
    advisory_timeout_seconds: float = Field(
        default=10.0, gt=0, description="Per-request timeout for advisory lookups."
    )
    advisory_cache_ttl_seconds: int = Field(
        default=21600,
        ge=0,
        description="TTL for cached advisories (0 disables caching).",
    )
    advisory_rate_limit_per_window: int = Field(
        default=60,
        ge=1,
        description="Advisory requests per window (GitHub allows 60/hour unauthenticated).",
    )
    advisory_rate_limit_window_seconds: float = Field(
        default=3600.0, gt=0, description="Length of the advisory rate-limit window (seconds)."
    )
    advisory_breaker_failure_threshold: int = Field(
        default=3, ge=1, description="Consecutive failures before the advisory circuit opens."
    )
    advisory_breaker_reset_seconds: float = Field(
        default=60.0, gt=0, description="How long the advisory circuit stays open before probing."
    )
    remediation_max_recommendations: int = Field(
        default=20,
        ge=1,
        description="Maximum recommendations per plan, so a noisy investigation stays actionable.",
    )

    # --- Notifications (Sprint 13) ------------------------------------------
    # The platform's only *outbound* integration. Every other adapter pulls;
    # these push, which is why nothing here runs without a recorded human
    # approval behind it (invariant #1).
    #
    # The default is no channels at all. An unconfigured deployment therefore
    # sends nothing and says so, rather than half-configuring its way into an
    # alert that goes to an address nobody reads.
    notification_channels: str = Field(
        default="",
        description="Ordered failover list, e.g. 'slack,email'. Empty disables alerting.",
    )
    notification_min_priority: TriagePriority = Field(
        default=TriagePriority.HIGH,
        description="Lowest triage priority that is worth waking someone for.",
    )
    notification_max_attempts: int = Field(
        default=3, ge=1, description="Attempts per channel before failing over to the next."
    )
    notification_retry_seconds: float = Field(
        default=2.0, gt=0, description="Backoff between attempts on the same channel."
    )
    notification_rate_limit_per_minute: int = Field(
        default=30,
        ge=1,
        description="Messages permitted per minute per channel, bounding an alert storm.",
    )
    notification_breaker_failure_threshold: int = Field(
        default=3, ge=1, description="Consecutive failures before a channel's circuit opens."
    )
    notification_breaker_reset_seconds: float = Field(
        default=60.0, gt=0, description="How long a channel's circuit stays open before probing."
    )

    # Slack. The webhook URL is a credential — it is a bearer capability to post
    # into a channel — so it is a secret, resolved from the secret store.
    slack_webhook_url: SecretStr = Field(
        default=SecretStr(""), description="Slack incoming-webhook URL."
    )
    slack_channel: str = Field(
        default="", description="Human-readable channel name, recorded as the recipient."
    )
    slack_timeout_seconds: float = Field(
        default=10.0, gt=0, description="Per-request timeout for Slack delivery."
    )

    # SMTP. Alerts are sent as text/plain and never as HTML: an alert about a
    # phishing URL that renders the URL as a clickable link is a self-own.
    smtp_host: str = Field(default="", description="SMTP relay host.")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP relay port.")
    smtp_username: str = Field(default="", description="SMTP username (empty for anonymous relay).")
    smtp_password: SecretStr = Field(default=SecretStr(""), description="SMTP password.")
    smtp_use_tls: bool = Field(
        default=True, description="Use STARTTLS. Disabling it outside local development is refused."
    )
    smtp_from_address: str = Field(default="", description="Envelope sender for outbound alerts.")
    smtp_recipients: str = Field(
        default="", description="Comma-separated default recipients for email alerts."
    )
    smtp_timeout_seconds: float = Field(
        default=15.0, gt=0, description="Per-message timeout for SMTP delivery."
    )

    # --- Analyst dashboard (Sprint 12) --------------------------------------
    # The SPA is served from its own origin, so the API has to name the origins
    # it will accept credentialed browser requests from. The default is the local
    # Vite dev server; every other environment supplies its own list. A wildcard
    # is deliberately impossible here: the browser refuses `*` with credentials,
    # and an API that answers any origin is one an attacker's page can read.
    cors_allowed_origins: str = Field(
        default="http://localhost:5173",
        description="Comma-separated browser origins permitted to call the API.",
    )
    investigation_page_size: int = Field(
        default=25, ge=1, le=200, description="Default investigations returned per page."
    )
    investigation_page_size_max: int = Field(
        default=100, ge=1, le=500, description="Upper bound a client may request per page."
    )
    stream_poll_seconds: float = Field(
        default=1.0,
        gt=0,
        description="How often the investigation stream re-reads authoritative state.",
    )
    stream_heartbeat_seconds: float = Field(
        default=15.0,
        gt=0,
        description="Idle interval after which the stream emits a keep-alive comment.",
    )
    stream_max_seconds: float = Field(
        default=1800.0,
        gt=0,
        description="Maximum lifetime of one stream connection before the client reconnects.",
    )

    @property
    def is_production(self) -> bool:
        """Whether the process is running in the production environment."""
        return self.environment is Environment.PRODUCTION

    @property
    def cors_origins(self) -> list[str]:
        """The configured browser origins, parsed and emptied of blanks."""
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @property
    def notification_channel_order(self) -> list[NotificationChannel]:
        """The configured failover order, as channels.

        Order is meaningful and is the operator's decision: it says which channel
        is tried first and what an outage falls back to. Unknown names are
        rejected at startup rather than silently dropped, because a typo that
        removes a channel is a typo that removes an alert.
        """
        return [
            NotificationChannel(name.strip())
            for name in self.notification_channels.split(",")
            if name.strip()
        ]

    @property
    def email_recipients(self) -> list[str]:
        """The configured default email recipients."""
        return [address.strip() for address in self.smtp_recipients.split(",") if address.strip()]

    @property
    def alerting_enabled(self) -> bool:
        """Whether any channel is configured to receive an alert."""
        return bool(self.notification_channel_order)

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
        if "*" in self.cors_origins:
            raise ValueError(
                "SOC_CORS_ALLOWED_ORIGINS must name explicit origins; "
                "'*' would let any page read authenticated API responses."
            )
        if self.investigation_page_size > self.investigation_page_size_max:
            raise ValueError(
                "SOC_INVESTIGATION_PAGE_SIZE must not exceed SOC_INVESTIGATION_PAGE_SIZE_MAX."
            )
        self._validate_notification_channels()
        return self

    def _validate_notification_channels(self) -> None:
        """Fail fast on a channel that is named but cannot actually deliver.

        A channel listed without its credentials is worse than one that is
        absent: the failover chain looks two deep and is one deep, and nobody
        discovers that until the first outage — which is exactly when the
        fallback was supposed to work.
        """
        try:
            channels = self.notification_channel_order
        except ValueError as exc:
            valid = ", ".join(member.value for member in NotificationChannel)
            raise ValueError(
                f"SOC_NOTIFICATION_CHANNELS names an unknown channel; expected one of: {valid}"
            ) from exc

        if len(set(channels)) != len(channels):
            raise ValueError("SOC_NOTIFICATION_CHANNELS lists the same channel more than once.")

        if NotificationChannel.SLACK in channels and not self.slack_webhook_url.get_secret_value():
            raise ValueError("SOC_SLACK_WEBHOOK_URL is required when 'slack' is a channel.")

        if NotificationChannel.EMAIL in channels:
            if not self.smtp_host:
                raise ValueError("SOC_SMTP_HOST is required when 'email' is a channel.")
            if not self.smtp_from_address:
                raise ValueError("SOC_SMTP_FROM_ADDRESS is required when 'email' is a channel.")
            if not self.email_recipients:
                raise ValueError("SOC_SMTP_RECIPIENTS is required when 'email' is a channel.")
            if self.is_production and not self.smtp_use_tls:
                raise ValueError("SOC_SMTP_USE_TLS must be true in the production environment.")

        if NotificationChannel.WEBHOOK in channels:
            # No generic-webhook adapter ships yet, and a configured channel with
            # no adapter behind it would silently swallow every alert routed to it.
            raise ValueError(
                "the 'webhook' channel has no adapter yet; use 'slack' and/or 'email'."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so configuration is resolved and validated exactly once per process.
    Tests that mutate the environment should call ``get_settings.cache_clear()``.
    """
    return Settings()

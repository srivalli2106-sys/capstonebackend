"""
config.py — Centralized application configuration.

All configuration is loaded from environment variables (and an optional
.env file) through a Pydantic Settings model.

Environments (APP_ENV):
  - development : permissive defaults, safe to run locally
  - test        : permissive defaults, for automated tests
  - production  : requires explicitly configured secrets and rejects
                  obviously unsafe placeholder values

Example:
    import os
    from server.config import Settings

    os.environ["APP_ENV"] = "production"
    os.environ["JWT_SECRET"] = "..."
    settings = Settings()
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Placeholder values that must never be accepted in production.
_INSECURE_JWT_SECRETS: Final = {
    "change-me-in-production-please",
    "dev-only-change-me",
    # Value shown in the committed .env.example placeholder.
    "change-me-to-a-long-random-string",
}

_MONGODB_PLACEHOLDER_MARKER: Final = "USERNAME:PASSWORD"

# Only symmetric HMAC algorithms make sense for the current shared-secret JWT
# design (public-key algorithms would need separate key configuration).
_SUPPORTED_JWT_ALGORITHMS: Final = frozenset({"HS256", "HS384", "HS512"})


class Settings(BaseSettings):
    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = "Secure Messaging API"
    app_version: str = "1.0.0"
    env: Literal["development", "test", "production"] = Field(
        default="development", validation_alias="APP_ENV"
    )
    debug: bool = Field(default=False, validation_alias="DEBUG")
    host: str = Field(default="0.0.0.0", validation_alias="HOST")
    port: int = Field(default=8000, validation_alias="PORT")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")

# ------------------------------------------------------------------
    # MongoDB
    # ------------------------------------------------------------------
    mongodb_uri: str = Field(
        default="mongodb://localhost:27017", validation_alias="MONGODB_URI"
    )
    mongodb_database: str = Field(
        default="secure_messaging", validation_alias="MONGODB_DB"
    )
    # Connection/pooling bounds (milliseconds). socketTimeoutMS may be unset,
    # in which case the driver default (no timeout) applies.
    mongodb_server_selection_timeout_ms: int = Field(
        default=5000, validation_alias="MONGODB_SERVER_SELECTION_TIMEOUT_MS", ge=100
    )
    mongodb_connect_timeout_ms: int = Field(
        default=10000, validation_alias="MONGODB_CONNECT_TIMEOUT_MS", ge=100
    )
    mongodb_socket_timeout_ms: int | None = Field(
        default=None, validation_alias="MONGODB_SOCKET_TIMEOUT_MS", ge=100
    )
    mongodb_max_pool_size: int = Field(
        default=50, validation_alias="MONGODB_MAX_POOL_SIZE", ge=1
    )
    mongodb_min_pool_size: int = Field(
        default=0, validation_alias="MONGODB_MIN_POOL_SIZE", ge=0
    )
    mongodb_max_idle_time_ms: int = Field(
        default=300000, validation_alias="MONGODB_MAX_IDLE_TIME_MS", ge=0
    )

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------
    redis_url: str = Field(
        default="redis://localhost:6379/0", validation_alias="REDIS_URL"
    )
    # Single reused client; the pool never exceeds this many connections.
    redis_max_connections: int = Field(
        default=10, validation_alias="REDIS_MAX_CONNECTIONS", ge=1
    )
    redis_socket_connect_timeout: float = Field(
        default=3.0, validation_alias="REDIS_SOCKET_CONNECT_TIMEOUT", ge=0
    )
    redis_socket_timeout: float = Field(
        default=5.0, validation_alias="REDIS_SOCKET_TIMEOUT", ge=0
    )
    redis_health_check_interval: int = Field(
        default=30, validation_alias="REDIS_HEALTH_CHECK_INTERVAL", ge=1
    )

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------
    jwt_secret: str = Field(
        default="change-me-in-production-please", validation_alias="JWT_SECRET"
    )
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    jwt_expiry_hours: int = Field(
        default=24, validation_alias="JWT_EXPIRY_HOURS"
    )
    # Issuer carried in every issued token and enforced on verification.
    jwt_issuer: str = Field(
        default="secure-messaging-api", validation_alias="JWT_ISSUER"
    )

    # ------------------------------------------------------------------
    # Authentication (proof of possession)
    # ------------------------------------------------------------------
    # Lifetime of a challenge issued by POST /auth/challenge before the
    # client must complete POST /auth/verify. Short by design: a stolen
    # challenge is only usable for this window.
    auth_challenge_ttl_seconds: int = Field(
        default=120, validation_alias="AUTH_CHALLENGE_TTL_SECONDS", ge=5
    )

    # ------------------------------------------------------------------
    # WebSocket
    # ------------------------------------------------------------------
    # Seconds a WebSocket client has to complete the first-frame auth
    # handshake before the server closes the connection (4001).
    ws_auth_timeout_seconds: float = Field(
        default=10.0, validation_alias="WS_AUTH_TIMEOUT_SECONDS", ge=1
    )
    # Hard per-process cap on concurrent WebSocket connections. The budget is
    # reserved before auth and released exactly once per disconnect.
    ws_max_connections: int = Field(
        default=1000, validation_alias="WS_MAX_CONNECTIONS", ge=1
    )
    # Per-IP cap on concurrent WebSocket connections (checked per connection,
    # pre-auth, alongside the global budget). 0 disables the check.
    ws_max_connections_per_ip: int = Field(
        default=20, validation_alias="WS_MAX_CONNECTIONS_PER_IP", ge=0
    )
    # Seconds a fully-authenticated connection may send no application frame
    # before the server closes it (1009/4008). 0 disables the idle timeout.
    # Requires the client/app-level keepalives (or the transport pings below).
    ws_idle_timeout_seconds: float = Field(
        default=180.0, validation_alias="WS_IDLE_TIMEOUT_SECONDS", ge=0
    )
    # Seconds between server-initiated WebSocket ping frames. Ought to be
    # smaller than ws_idle_timeout_seconds: healthy idle connections answer
    # with a pong that resets the idle window. 0 disables the keepalive.
    ws_keepalive_seconds: float = Field(
        default=30.0, validation_alias="WS_KEEPALIVE_SECONDS", ge=0
    )
    # Lifetime of presence/connection markers in Redis ("online:" and
    # "conn:" keys). Must comfortably exceed the heartbeat gap; the server
    # refreshes the marker every half-life while a connection is alive.
    ws_presence_ttl_seconds: int = Field(
        default=300, validation_alias="WS_PRESENCE_TTL_SECONDS", ge=30
    )
    # Redis sliding-window rate limits for the WebSocket path.
    ws_connect_rate_per_minute: int = Field(
        default=60, validation_alias="WS_CONNECT_RATE_PER_MINUTE", ge=1
    )
    ws_message_rate_per_minute: int = Field(
        default=120, validation_alias="WS_MESSAGE_RATE_PER_MINUTE", ge=1
    )

# ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    # Raw env value. ``None`` means the env var is unset; an explicit empty
    # string ("") or whitespace-only value means the operator intentionally
    # configured no origins (e.g. production with no frontend yet). The
    # ``cors_origins_list`` property below resolves these three states
    # distinctly. We deliberately do NOT default to "*" so that pydantic
    # Settings does not collapse "unset" and "explicitly empty" into the same
    # value, which would otherwise cause an explicit empty CORS_ORIGINS in
    # production to be misread as a wildcard (and rejected by the production
    # validator).
    cors_origins: str | None = Field(default=None, validation_alias="CORS_ORIGINS")

    # ------------------------------------------------------------------
    # Security / transport
    # ------------------------------------------------------------------
    # Comma-separated list of acceptable Host header values. "*" (the
    # development default) disables host validation entirely; production
    # must list explicit hosts.
    allowed_hosts: str = Field(default="*", validation_alias="ALLOWED_HOSTS")
    # True when this deployment is served over TLS (HTTPS/WSS). Required in
    # production; gates Strict-Transport-Security so the header is never sent
    # over plaintext local HTTP.
    secure_transport: bool = Field(default=False, validation_alias="SECURE_TRANSPORT")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Resolve ``cors_origins`` into a list suitable for Starlette's
        ``CORSMiddleware.allow_origins``.

        The three operator-intended states are preserved distinctly:

        - env var unset (``None``) — fall back to the development default
          ``["*"]`` so local workflows keep working unchanged.
        - env var set but empty / whitespace-only — explicitly configured
          "no browser origins allowed" (e.g. production deployment with no
          frontend). Resolves to ``[]``. Starlette treats an empty
          ``allow_origins`` list as "no origins permitted": CORS preflight and
          actual cross-origin browser requests are rejected (no
          ``Access-Control-Allow-Origin`` is sent), while same-origin and
          non-browser requests still succeed. This is the secure choice when
          no client web app exists yet, and is accepted by the production
          validator.
        - env var set to one or more comma-separated values — each non-empty
          trimmed entry becomes a list element. An explicit ``"*"`` is
          preserved and remains rejected in production by the production
          validator (see ``_check_production``).
        """
        raw = self.cors_origins
        if raw is None:
            return ["*"]
        if not raw.strip():
            return []
        origins = [origin.strip() for origin in raw.split(",")]
        origins = [origin for origin in origins if origin]
        if not origins:
            return []
        return origins

    @property
    def allowed_hosts_list(self) -> list[str]:
        """Return allowed Host header values as a non-empty trimmed list.

        An unset/empty value resolves to ``["*"]`` (no host validation),
        matching the development default; production validation rejects it.
        """
        hosts = [host.strip() for host in self.allowed_hosts.split(",")]
        hosts = [host for host in hosts if host]
        return hosts or ["*"]

    @model_validator(mode="after")
    def _check_jwt_algorithm(self) -> Settings:
        # Enforced in every environment: an unsupported algorithm (e.g.
        # "none") must never be configured, as verification is pinned to the
        # configured algorithm list.
        if self.jwt_algorithm not in _SUPPORTED_JWT_ALGORITHMS:
            raise ValueError(
                "JWT_ALGORITHM must be one of "
                f"{sorted(_SUPPORTED_JWT_ALGORITHMS)}, got {self.jwt_algorithm!r}."
            )
        if not self.jwt_issuer.strip():
            raise ValueError("JWT_ISSUER must not be empty.")
        return self

    @model_validator(mode="after")
    def _check_production(self) -> Settings:
        if self.env != "production":
            return self

        if not self.jwt_secret or len(self.jwt_secret) < 16:
            raise ValueError(
                "JWT_SECRET must be set and at least 16 characters long in "
                "production."
            )
        if self.jwt_secret in _INSECURE_JWT_SECRETS:
            raise ValueError(
                "JWT_SECRET must not be a known placeholder value in production."
            )
        if _MONGODB_PLACEHOLDER_MARKER in self.mongodb_uri:
            raise ValueError(
"MONGODB_URI must be a real connection string in production."
            )
        if self.cors_origins_list == ["*"]:
            raise ValueError(
                "CORS_ORIGINS must list specific origins in production "
                "(the wildcard '*' is not allowed)."
            )
        if self.allowed_hosts_list == ["*"]:
            raise ValueError(
                "ALLOWED_HOSTS must list specific hosts in production "
                "(the wildcard '*' is not allowed)."
            )
        if not self.secure_transport:
            raise ValueError(
                "SECURE_TRANSPORT must be enabled in production: the API must "
                "be served over HTTPS and WSS (typically behind a "
                "TLS-terminating proxy)."
            )
        return self


settings = Settings()

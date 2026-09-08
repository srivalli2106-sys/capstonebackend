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
}

_MONGODB_PLACEHOLDER_MARKER: Final = "USERNAME:PASSWORD"


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

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------
    redis_url: str = Field(
        default="redis://localhost:6379/0", validation_alias="REDIS_URL"
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

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    cors_origins: str = Field(default="*", validation_alias="CORS_ORIGINS")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS origins as a non-empty list of trimmed values.

        "*" is preserved for development so existing behavior is unchanged
        unless the caller explicitly configures specific origins.
        """
        origins = [origin.strip() for origin in self.cors_origins.split(",")]
        origins = [origin for origin in origins if origin]
        return origins or ["*"]

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
        return self


settings = Settings()

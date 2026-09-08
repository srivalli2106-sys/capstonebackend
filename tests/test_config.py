"""Centralized configuration tests (no external infrastructure required)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from server.config import Settings

# Every env var the app reads, with sane dev defaults.
_BASE_ENV = {
    "APP_ENV": "development",
    "DEBUG": "false",
    "HOST": "0.0.0.0",
    "PORT": "8000",
    "LOG_LEVEL": "INFO",
    "MONGODB_URI": "mongodb://localhost:27017",
    "MONGODB_DB": "secure_messaging",
    "REDIS_URL": "redis://localhost:6379/0",
    "JWT_SECRET": "change-me-in-production-please",
    "JWT_ALGORITHM": "HS256",
    "JWT_EXPIRY_HOURS": "24",
    "CORS_ORIGINS": "*",
}

_VALID_PROD = {
    "APP_ENV": "production",
    "JWT_SECRET": "s" * 32,
    "MONGODB_URI": "mongodb+srv://realuser:realpass@cluster0.mongodb.net",
    "CORS_ORIGINS": "https://app.example.com",
}


def load(monkeypatch, **overrides) -> Settings:
    """Build a Settings from an env dict, isolated from any real .env file."""
    env = dict(_BASE_ENV)
    env.update(overrides)
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    return Settings(_env_file=None)


def test_dev_defaults(monkeypatch):
    s = load(monkeypatch)
    assert s.env == "development"
    assert s.debug is False
    assert s.port == 8000
    assert s.mongodb_uri == "mongodb://localhost:27017"
    assert s.mongodb_database == "secure_messaging"
    assert s.jwt_secret == "change-me-in-production-please"
    assert s.jwt_expiry_hours == 24
    assert s.cors_origins_list == ["*"]


def test_env_validation_aliases(monkeypatch):
    s = load(monkeypatch, PORT="9000", MONGODB_DB="otherdb", JWT_EXPIRY_HOURS="48")
    assert s.port == 9000
    assert s.mongodb_database == "otherdb"
    assert s.jwt_expiry_hours == 48


def test_test_env_allows_permissive_defaults(monkeypatch):
    s = load(monkeypatch, APP_ENV="test")
    assert s.env == "test"
    assert s.cors_origins_list == ["*"]


def test_invalid_env_value_rejected(monkeypatch):
    with pytest.raises(ValidationError):
        load(monkeypatch, APP_ENV="dev")


@pytest.mark.parametrize(
    "bad",
    [
        {"APP_ENV": "production"},  # placeholder JWT secret
        {"APP_ENV": "production", "JWT_SECRET": "short"},
        {"APP_ENV": "production", "JWT_SECRET": None},  # missing secret
        {
            "APP_ENV": "production",
            "JWT_SECRET": "s" * 32,
            "MONGODB_URI": "mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net",
        },
        {
            "APP_ENV": "production",
            "JWT_SECRET": "s" * 32,
            "MONGODB_URI": "mongodb+srv://realuser:realpass@cluster0.mongodb.net",
            "CORS_ORIGINS": "*",
        },
    ],
)
def test_production_rejects_unsafe_values(monkeypatch, bad):
    with pytest.raises(ValidationError):
        load(monkeypatch, **bad)


def test_valid_production_loads(monkeypatch):
    s = load(monkeypatch, **_VALID_PROD)
    assert s.env == "production"
    assert s.jwt_secret == "s" * 32


def test_cors_origins_list_parsing(monkeypatch):
    assert load(monkeypatch, CORS_ORIGINS="https://a.com, https://b.com").cors_origins_list == [
        "https://a.com",
        "https://b.com",
    ]
    assert load(monkeypatch, CORS_ORIGINS="https://a.com, , https://b.com").cors_origins_list == [
        "https://a.com",
        "https://b.com",
    ]
    assert load(monkeypatch, CORS_ORIGINS="" ).cors_origins_list == ["*"]
    assert load(monkeypatch, CORS_ORIGINS=" ").cors_origins_list == ["*"]

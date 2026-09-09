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
    "ALLOWED_HOSTS": "api.example.com",
    "SECURE_TRANSPORT": "true",
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
    assert s.allowed_hosts_list == ["*"]
    assert s.secure_transport is False


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
        {
            # Valid prod except wildcard ALLOWED_HOSTS.
            "APP_ENV": "production",
            "JWT_SECRET": "s" * 32,
            "MONGODB_URI": "mongodb+srv://realuser:realpass@cluster0.mongodb.net",
            "CORS_ORIGINS": "https://app.example.com",
            "ALLOWED_HOSTS": "*",
            "SECURE_TRANSPORT": "true",
        },
        {
            # Valid prod except missing SECURE_TRANSPORT.
            "APP_ENV": "production",
            "JWT_SECRET": "s" * 32,
            "MONGODB_URI": "mongodb+srv://realuser:realpass@cluster0.mongodb.net",
            "CORS_ORIGINS": "https://app.example.com",
            "ALLOWED_HOSTS": "api.example.com",
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
    assert s.allowed_hosts_list == ["api.example.com"]
    assert s.secure_transport is True


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


def test_allowed_hosts_list_parsing(monkeypatch):
    assert load(
        monkeypatch, ALLOWED_HOSTS="api.example.com, localhost"
    ).allowed_hosts_list == ["api.example.com", "localhost"]
    assert load(monkeypatch, ALLOWED_HOSTS="api.example.com, ,localhost").allowed_hosts_list == [
        "api.example.com",
        "localhost",
    ]
    assert load(monkeypatch, ALLOWED_HOSTS="").allowed_hosts_list == ["*"]
    assert load(monkeypatch, ALLOWED_HOSTS=" ").allowed_hosts_list == ["*"]


def test_secure_transport_parsed_from_env(monkeypatch):
    assert load(monkeypatch, SECURE_TRANSPORT="true").secure_transport is True
    assert load(monkeypatch, SECURE_TRANSPORT="false").secure_transport is False


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_supported_jwt_algorithms_accepted(monkeypatch, alg):
    s = load(monkeypatch, JWT_ALGORITHM=alg)
    assert s.jwt_algorithm == alg


@pytest.mark.parametrize("alg", ["none", "RS256", "ES256", ""])
def test_unsupported_jwt_algorithm_rejected(monkeypatch, alg):
    with pytest.raises(ValidationError):
        load(monkeypatch, JWT_ALGORITHM=alg)


def test_jwt_issuer_defaults_and_parses(monkeypatch):
    assert load(monkeypatch).jwt_issuer == "secure-messaging-api"
    assert load(monkeypatch, JWT_ISSUER="custom-iss").jwt_issuer == "custom-iss"


def test_empty_jwt_issuer_rejected(monkeypatch):
    with pytest.raises(ValidationError):
        load(monkeypatch, JWT_ISSUER="  ")


def test_auth_challenge_ttl_defaults_and_parses(monkeypatch):
    assert load(monkeypatch).auth_challenge_ttl_seconds == 120
    assert load(monkeypatch, AUTH_CHALLENGE_TTL_SECONDS="60").auth_challenge_ttl_seconds == 60


def test_auth_challenge_ttl_minimum_enforced(monkeypatch):
    with pytest.raises(ValidationError):
        load(monkeypatch, AUTH_CHALLENGE_TTL_SECONDS="1")


def test_ws_settings_defaults(monkeypatch):
    s = load(monkeypatch)
    assert s.ws_auth_timeout_seconds == 10.0
    assert s.ws_max_connections == 1000
    assert s.ws_presence_ttl_seconds == 300
    assert s.ws_connect_rate_per_minute == 60
    assert s.ws_message_rate_per_minute == 120


def test_ws_settings_env_overrides(monkeypatch):
    s = load(
        monkeypatch,
        WS_AUTH_TIMEOUT_SECONDS="5",
        WS_MAX_CONNECTIONS="50",
        WS_PRESENCE_TTL_SECONDS="120",
        WS_CONNECT_RATE_PER_MINUTE="30",
        WS_MESSAGE_RATE_PER_MINUTE="10",
    )
    assert s.ws_auth_timeout_seconds == 5.0
    assert s.ws_max_connections == 50
    assert s.ws_presence_ttl_seconds == 120
    assert s.ws_connect_rate_per_minute == 30
    assert s.ws_message_rate_per_minute == 10


@pytest.mark.parametrize(
    "bad",
    [
        {"WS_AUTH_TIMEOUT_SECONDS": "0"},
        {"WS_MAX_CONNECTIONS": "0"},
        {"WS_PRESENCE_TTL_SECONDS": "10"},
        {"WS_CONNECT_RATE_PER_MINUTE": "0"},
        {"WS_MESSAGE_RATE_PER_MINUTE": "0"},
    ],
)
def test_ws_settings_minimums_enforced(monkeypatch, bad):
    with pytest.raises(ValidationError):
        load(monkeypatch, **bad)

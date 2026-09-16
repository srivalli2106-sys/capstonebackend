"""Health endpoint and app wiring tests (no external infrastructure)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError

import server.app as app_module
from server.app import app
from server.config import settings


def test_health_returns_ok(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_app_metadata_comes_from_settings(client: TestClient):
    assert app.title == settings.app_name
    assert app.version == settings.app_version


def test_cors_origins_come_from_settings(client: TestClient):
    cors = next(
        m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware"
    )
    assert cors.kwargs["allow_origins"] == settings.cors_origins_list


def test_health_ready_when_all_dependencies_healthy(client, monkeypatch):
    async def ok(_=None):
        return True

    monkeypatch.setattr(app_module, "ping_mongo", ok)
    monkeypatch.setattr(app_module, "ping_redis", ok)
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_health_ready_503_when_mongodb_down(client, monkeypatch):
    async def fail_mongo(_=None):
        raise PyMongoError("mongodb down")

    async def ok(_=None):
        return True

    monkeypatch.setattr(app_module, "ping_mongo", fail_mongo)
    monkeypatch.setattr(app_module, "ping_redis", ok)
    response = client.get("/health/ready")
    assert response.status_code == 503


def test_health_ready_503_when_redis_down(client, monkeypatch):
    async def ok(_=None):
        return True

    async def fail_redis(_=None):
        raise RedisError("redis down")

    monkeypatch.setattr(app_module, "ping_mongo", ok)
    monkeypatch.setattr(app_module, "ping_redis", fail_redis)
    response = client.get("/health/ready")
    assert response.status_code == 503


def test_health_ready_does_not_leak_infrastructure_details(client, monkeypatch):
    async def fail_mongo(_=None):
        raise PyMongoError("mongodb down with sensitive host details")

    async def ok(_=None):
        return True

    monkeypatch.setattr(app_module, "ping_mongo", fail_mongo)
    monkeypatch.setattr(app_module, "ping_redis", ok)
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert "mongodb" not in response.text
    assert "host" not in response.text

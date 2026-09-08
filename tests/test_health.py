"""Health endpoint and app wiring tests (no external infrastructure)."""

from __future__ import annotations

from fastapi.testclient import TestClient

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

"""Driver-failure -> HTTP 503 dependency_unavailable tests (no infra required).

Phase 4 contract: only the driver exception classes (PyMongoError, RedisError)
render as a stable 503 with a generic message — the underlying driver detail
is never included in the response, and programming errors still reach the
generic 500 handler.
"""

from __future__ import annotations

import json

from fastapi import Request
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError

from server.exceptions import dependency_error_handler


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("10.0.0.1", 1234),
            "headers": [(b"host", b"testserver")],
        }
    )


def _check_503(body: dict) -> None:
    assert body["error"]["code"] == "dependency_unavailable"
    assert body["error"]["message"] == "Dependency unavailable"
    assert "request_id" in body["error"]


async def test_pymongo_error_renders_503_without_leaking_detail():
    resp = await dependency_error_handler(
        _request(), PyMongoError("secret-detail: mongodb://user:pass@host")
    )
    assert resp.status_code == 503
    _check_503(json.loads(resp.body))
    assert "secret-detail" not in resp.body.decode()


async def test_redis_error_renders_503_without_leaking_detail():
    resp = await dependency_error_handler(
        _request(), RedisError("secret-detail: redis://:pass@host:6379")
    )
    assert resp.status_code == 503
    _check_503(json.loads(resp.body))
    assert "secret-detail" not in resp.body.decode()


async def test_mongo_failure_surfaces_as_503_through_app(client, monkeypatch):
    from server.routes import auth as auth_module

    async def _boom(*args, **kwargs):
        raise PyMongoError("mongodb down")

    async def _no_rate_limit(request, category: str = "general"):
        return None

    monkeypatch.setattr(auth_module, "check_rate_limit", _no_rate_limit)
    monkeypatch.setattr("server.db.get_user", _boom)

    resp = client.post("/auth/login", json={"user_id": "alice"})
    assert resp.status_code == 503
    _check_503(resp.json())
    assert "mongodb down" not in resp.text


async def test_redis_failure_surfaces_as_503_through_app(client, monkeypatch):
    from server import middleware as middleware_module

    async def _boom():
        raise RedisError("redis down")

    monkeypatch.setattr(middleware_module, "get_redis", _boom)

    resp = client.post("/auth/login", json={"user_id": "alice"})
    assert resp.status_code == 503
    _check_503(resp.json())
    assert "redis down" not in resp.text

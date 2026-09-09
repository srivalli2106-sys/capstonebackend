"""Phase 5 security-hardening tests (no external infrastructure required).

Covers security headers (with HSTS gated on secure transport), CORS behavior,
Host allowlisting with the Phase-3 error contract, JWT algorithm pinning,
input length bounds, and absence of secrets in logs.
"""

from __future__ import annotations

import json
import logging

import jwt
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from server.middleware import create_token, decode_token
from server.request_id import RequestIDMiddleware
from server.routes.messages import _MAX_WS_MESSAGE_CHARS, _handle_message
from server.security import AllowedHostsMiddleware, SecurityHeadersMiddleware

# ---------------------------------------------------------------------------
# Mini apps mirroring the app's middleware wiring
# ---------------------------------------------------------------------------


def _cors_app() -> TestClient:
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://client.example.com", "https://alt.example.com"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return TestClient(app)


def _host_app() -> FastAPI:
    """Mirror app.py's wiring (AllowedHosts innermost, then CORS, RequestID,
    SecurityHeaders) so rejection responses are stamped by the header
    middlewares exactly like the real application."""
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.add_middleware(
        AllowedHostsMiddleware,
        allowed_hosts=["api.example.com", "localhost", "127.0.0.1"],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://client.example.com"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=False)
    return app


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


def test_security_headers_present_on_success(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    # Test env is not secure transport -> HSTS must NOT be sent.
    assert "strict-transport-security" not in resp.headers


def test_security_headers_present_on_error(client):
    resp = client.get("/definitely-not-a-route")
    assert resp.status_code == 404
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    # Request-ID correlation header must survive alongside security headers.
    assert resp.headers.get("x-request-id")


@pytest.mark.parametrize("hsts_enabled", [True, False])
def test_hsts_gated_on_secure_transport(hsts_enabled):
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=hsts_enabled)
    resp = TestClient(app).get("/health")
    if hsts_enabled:
        assert (
            resp.headers["strict-transport-security"]
            == "max-age=31536000; includeSubDomains"
        )
    else:
        assert "strict-transport-security" not in resp.headers


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_cors_allowed_origin_granted():
    resp = _cors_app().get(
        "/health", headers={"Origin": "https://client.example.com"}
    )
    assert resp.status_code == 200
    assert (
        resp.headers.get("access-control-allow-origin")
        == "https://client.example.com"
    )


def test_cors_second_configured_origin_granted():
    resp = _cors_app().get("/health", headers={"Origin": "https://alt.example.com"})
    assert (
        resp.headers.get("access-control-allow-origin") == "https://alt.example.com"
    )


def test_cors_disallowed_origin_not_permitted():
    resp = _cors_app().get(
        "/health", headers={"Origin": "https://evil.example.com"}
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") is None


# ---------------------------------------------------------------------------
# Host validation
# ---------------------------------------------------------------------------


def test_allowed_hosts_mini_app_allows_listed_host():
    resp = TestClient(_host_app(), base_url="http://api.example.com").get("/health")
    assert resp.status_code == 200


def test_allowed_hosts_mini_app_allows_ipv6_like_and_port():
    resp = TestClient(_host_app(), base_url="http://api.example.com:8443").get(
        "/health"
    )
    assert resp.status_code == 200


def test_allowed_hosts_mini_app_allows_localhost_in_list():
    resp = TestClient(_host_app(), base_url="http://localhost").get("/health")
    assert resp.status_code == 200


def test_allowed_hosts_mini_app_rejects_unknown_host_with_contract():
    resp = TestClient(_host_app(), base_url="http://evil.example.com").get("/health")
    assert resp.status_code == 400
    body = resp.json()["error"]
    assert body["code"] == "invalid_host"
    assert body["message"]
    # Rejection flows back through RequestIDMiddleware and
    # SecurityHeadersMiddleware, so it must carry a real request ID and the
    # security headers -- not the "-" fallback.
    assert body["request_id"] != "-"
    assert resp.headers["x-request-id"] == body["request_id"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"


# ---------------------------------------------------------------------------
# JWT algorithm pinning
# ---------------------------------------------------------------------------


def test_decode_token_rejects_alg_none():
    token = jwt.encode({"user_id": "alice"}, None, algorithm="none")
    with pytest.raises(HTTPException) as excinfo:
        decode_token(token)
    assert excinfo.value.status_code == 401


# ---------------------------------------------------------------------------
# Input length bounds
# ---------------------------------------------------------------------------

_IK_64 = "ab" * 32


def test_register_user_id_over_limit_rejected(client):
    resp = client.post(
        "/auth/register",
        json={"user_id": "a" * 65, "ik_public": _IK_64},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_register_identity_key_over_limit_rejected(client):
    resp = client.post(
        "/auth/register",
        json={"user_id": "alice", "ik_public": "ab" * 65},
    )
    assert resp.status_code == 422


def test_login_user_id_over_limit_rejected(client):
    resp = client.post("/auth/login", json={"user_id": "a" * 65})
    assert resp.status_code == 422


def test_key_bundle_fields_over_limit_rejected(client, monkeypatch):
    token = create_token("carol")
    headers = {"Authorization": f"Bearer {token}"}

    # require_auth checks revocation (fail closed); neutralize it here so
    # request-body validation (422) is what we assert on.
    async def _not_revoked(jti: str) -> bool:
        return False

    monkeypatch.setattr(
        "server.auth_service.auth_store.is_token_revoked", _not_revoked
    )

    for field in ("spk_public", "spk_sig", "opk_public"):
        body = {"spk_public": "cd" * 32, "spk_sig": "ef" * 32, field: "ab" * 65}
        resp = client.post("/keys/upload", json=body, headers=headers)
        assert resp.status_code == 422, field


# ---------------------------------------------------------------------------
# WebSocket frame bounds (unit-level, no Redis needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oversized_ws_frame_dropped(monkeypatch, caplog):
    async def fail_redis(**kwargs):
        raise AssertionError("redis must not be touched for oversized frames")

    monkeypatch.setattr("server.routes.messages.is_online", fail_redis)
    with caplog.at_level(logging.WARNING, logger="server.routes.messages"):
        await _handle_message("alice", "x" * (_MAX_WS_MESSAGE_CHARS + 1))
    assert "dropping oversized websocket message" in caplog.text
    assert "alice" in caplog.text
    assert "x" * 100 not in caplog.text  # payload content never logged


@pytest.mark.asyncio
async def test_ws_frame_invalid_recipient_dropped(monkeypatch, caplog):
    async def fail_redis(**kwargs):
        raise AssertionError("redis must not be touched for invalid recipients")

    monkeypatch.setattr("server.routes.messages.is_online", fail_redis)
    raw = json.dumps({"to": "r" * 65, "data": "not-an-encrypted-blob"})
    with caplog.at_level(logging.WARNING, logger="server.routes.messages"):
        await _handle_message("alice", raw)
    assert "invalid recipient" in caplog.text
    assert "not-an-encrypted-blob" not in caplog.text


# ---------------------------------------------------------------------------
# Secrets never appear in logs
# ---------------------------------------------------------------------------


def test_logs_do_not_contain_bearer_token(client, caplog):
    token = create_token("alice")
    with caplog.at_level(logging.INFO, logger="server.request_id"):
        client.get("/health", headers={"Authorization": f"Bearer {token}"})
    for record in caplog.records:
        assert token not in record.getMessage()
        assert "Bearer" not in record.getMessage()

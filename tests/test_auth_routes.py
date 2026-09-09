"""HTTP contract tests for the Phase 6 /auth endpoints.

Runs the real app (middleware, security headers, error envelope, request IDs)
with the auth_service's DB lookups and the auth_store's Redis surface
replaced by fakes. No external infrastructure.
"""

from __future__ import annotations

import logging

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.config import settings
from server.jwt_auth import create_access_token, verify_access_token


class FakeRedis:
    def __init__(self, raise_errors: bool = False):
        self._data: dict[str, str] = {}
        self._ttls: dict[str, int] = {}
        self.raise_errors = raise_errors

    async def set(self, name, value, ex=None):
        if self.raise_errors:
            raise RuntimeError("redis down")
        self._data[name] = value
        if ex is not None:
            self._ttls[name] = ex
        return True

    async def getdel(self, name):
        if self.raise_errors:
            raise RuntimeError("redis down")
        return self._data.pop(name, None)

    async def exists(self, name):
        if self.raise_errors:
            raise RuntimeError("redis down")
        return 1 if name in self._data else 0


def _keypair(user_id: str):
    private = Ed25519PrivateKey.generate()
    return {
        "user_id": user_id,
        "ik_public": private.public_key().public_bytes_raw(),
        "private": private,
    }


def _patch_env(monkeypatch, user: dict | None, fake: FakeRedis) -> None:
    async def _no_rate_limit(request, category: str = "general"):
        return None

    async def _get_user(user_id: str):
        return user

    async def _get_redis():
        return fake

    monkeypatch.setattr("server.routes.auth.check_rate_limit", _no_rate_limit)
    monkeypatch.setattr("server.db.get_user", _get_user)
    monkeypatch.setattr("server.auth_store.get_redis", _get_redis)


def _sign(user: dict, nonce: str) -> str:
    return user["private"].sign(bytes.fromhex(nonce)).hex()


# ---------------------------------------------------------------------------
# POST /auth/challenge
# ---------------------------------------------------------------------------


def test_challenge_succeeds_for_valid_user(client, monkeypatch):
    user = _keypair("alice")
    fake = FakeRedis()
    _patch_env(monkeypatch, user, fake)

    resp = client.post("/auth/challenge", json={"user_id": "alice"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["user_id"] == "alice"
    nonce = body["nonce"]
    assert len(nonce) == 64 and len(bytes.fromhex(nonce)) == 32  # 32-byte nonce
    assert fake._data["auth_challenge:alice"] == nonce
    assert fake._ttls["auth_challenge:alice"] == settings.auth_challenge_ttl_seconds


def test_challenge_unknown_user_is_404(client, monkeypatch):
    _patch_env(monkeypatch, None, FakeRedis())
    resp = client.post("/auth/challenge", json={"user_id": "ghost"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_challenge_invalid_input_is_422(client, monkeypatch):
    _patch_env(monkeypatch, _keypair("alice"), FakeRedis())
    resp = client.post("/auth/challenge", json={"user_id": "a" * 65})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


# ---------------------------------------------------------------------------
# POST /auth/verify
# ---------------------------------------------------------------------------


def _challenge(client, monkeypatch, user) -> str:
    _patch_env(monkeypatch, user, FakeRedis())
    resp = client.post("/auth/challenge", json={"user_id": user["user_id"]})
    assert resp.status_code == 200
    return resp.json()["nonce"]


def test_valid_ed25519_signature_verifies(client, monkeypatch):
    user = _keypair("alice")
    nonce = _challenge(client, monkeypatch, user)

    resp = client.post(
        "/auth/verify",
        json={"user_id": "alice", "nonce": nonce, "signature": _sign(user, nonce)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["user_id"] == "alice"
    assert verify_access_token(body["token"])["sub"] == "alice"


def test_malformed_nonce_rejected(client, monkeypatch):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())
    resp = client.post(
        "/auth/verify",
        json={"user_id": "alice", "nonce": "z" * 64, "signature": "ab" * 64},
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "payload",
    [
        {"nonce": "ab" * 24, "signature": "ab" * 64},  # nonce wrong length
        {"nonce": "ab" * 32, "signature": "ab" * 48},  # signature too short
    ],
)
def test_wrong_length_inputs_rejected_as_422(client, monkeypatch, payload):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())
    resp = client.post(
        "/auth/verify",
        json={"user_id": "alice", "nonce": payload["nonce"], "signature": payload["signature"]},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_invalid_signature_rejected(client, monkeypatch):
    user = _keypair("alice")
    nonce = _challenge(client, monkeypatch, user)
    other = _keypair("mallory")

    resp = client.post(
        "/auth/verify",
        json={"user_id": "alice", "nonce": nonce, "signature": _sign(other, nonce)},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["message"] == "Authentication failed"


def test_missing_challenge_rejected(client, monkeypatch):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())  # no challenge issued
    resp = client.post(
        "/auth/verify",
        json={"user_id": "alice", "nonce": "aa" * 32, "signature": "bb" * 64},
    )
    assert resp.status_code == 401


def test_replay_of_challenge_fails(client, monkeypatch):
    user = _keypair("alice")
    nonce = _challenge(client, monkeypatch, user)
    signature = _sign(user, nonce)
    body = {"user_id": "alice", "nonce": nonce, "signature": signature}

    assert client.post("/auth/verify", json=body).status_code == 200
    assert client.post("/auth/verify", json=body).status_code == 401


def test_verify_failure_keeps_structured_contract_and_request_id(client, monkeypatch):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())
    resp = client.post(
        "/auth/verify",
        json={"user_id": "alice", "nonce": "aa" * 32, "signature": "bb" * 64},
    )
    assert resp.status_code == 401
    error = resp.json()["error"]
    assert error["code"] == "http_401"
    assert error["message"] == "Authentication failed"
    assert error["request_id"] == resp.headers.get("x-request-id")


# ---------------------------------------------------------------------------
# POST /auth/logout (Bearer JWT)
# ---------------------------------------------------------------------------


def test_logout_requires_token(client, monkeypatch):
    _patch_env(monkeypatch, _keypair("alice"), FakeRedis())
    resp = client.post("/auth/logout")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "http_401"


def test_logout_revokes_and_revoked_token_rejected(client, monkeypatch):
    user = _keypair("alice")
    fake = FakeRedis()
    _patch_env(monkeypatch, user, fake)

    token = create_access_token("alice")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/auth/logout", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"status": "logged_out"}

    jti = verify_access_token(token)["jti"]
    assert fake._data.get(f"auth_revoked:{jti}") == "1"

    # Same token is now rejected on further authenticated calls.
    assert client.post("/auth/logout", headers=headers).status_code == 401
    assert client.get("/keys/prekeys/target", headers=headers).status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/login (development-only)
# ---------------------------------------------------------------------------


def test_login_works_outside_production(client, monkeypatch):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())
    resp = client.post("/auth/login", json={"user_id": "alice"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["user_id"] == "alice"
    assert verify_access_token(body["token"])["sub"] == "alice"


def test_login_unknown_user_is_404(client, monkeypatch):
    _patch_env(monkeypatch, None, FakeRedis())
    resp = client.post("/auth/login", json={"user_id": "ghost"})
    assert resp.status_code == 404


def test_login_disabled_in_production(client, monkeypatch):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())
    monkeypatch.setattr(settings, "env", "production")
    resp = client.post("/auth/login", json={"user_id": "alice"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


# ---------------------------------------------------------------------------
# Rate limiting is applied per endpoint
# ---------------------------------------------------------------------------


def test_auth_endpoints_apply_rate_limits(client, monkeypatch):
    user = _keypair("alice")
    fake = FakeRedis()
    recorded: list[str] = []

    async def _record(request, category: str = "general"):
        recorded.append(category)

    monkeypatch.setattr("server.routes.auth.check_rate_limit", _record)
    monkeypatch.setattr("server.db.get_user", _get_user_of(user))

    async def _get_redis():
        return fake

    monkeypatch.setattr("server.auth_store.get_redis", _get_redis)

    client.post("/auth/challenge", json={"user_id": "alice"})
    client.post(
        "/auth/verify",
        json={
            "user_id": "alice",
            "nonce": fake._data["auth_challenge:alice"],
            "signature": _sign(user, fake._data["auth_challenge:alice"]),
        },
    )
    client.post(
        "/auth/logout", headers={"Authorization": f"Bearer {create_access_token('alice')}"}
    )

    assert recorded == ["challenge", "verify", "logout"]


def _get_user_of(user):
    async def _get_user(user_id: str):
        return user

    return _get_user


# ---------------------------------------------------------------------------
# Sensitive material is never logged
# ---------------------------------------------------------------------------


def test_no_auth_sensitive_material_in_logs(client, monkeypatch, caplog):
    user = _keypair("alice")
    _patch_env(monkeypatch, user, FakeRedis())

    with caplog.at_level(logging.INFO):
        challenge = client.post("/auth/challenge", json={"user_id": "alice"}).json()
        nonce = challenge["nonce"]
        signature = _sign(user, nonce)
        verified = client.post(
            "/auth/verify",
            json={"user_id": "alice", "nonce": nonce, "signature": signature},
        ).json()
        token = verified["token"]
        client.post(
            "/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )
        client.post(
            "/auth/verify",
            json={"user_id": "alice", "nonce": nonce, "signature": signature},
        )  # a failure path, too

    text = caplog.text
    assert nonce not in text
    assert signature not in text
    assert token not in text

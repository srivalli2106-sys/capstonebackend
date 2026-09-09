"""Authentication service tests (no external infrastructure).

Patches the auth_service's DB lookups and the auth_store's Redis surface to
focused fakes; exercises real Ed25519 signing/verification and real JWT
creation. Verifies fail-closed behaviour and the generic 401 contract.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from redis.exceptions import RedisError

from server import auth_service, auth_store
from server.auth_service import (
    create_challenge,
    development_login,
    require_auth,
    revoke_token,
    verify_credentials,
)
from server.config import settings
from server.exceptions import ResourceNotFound
from server.jwt_auth import create_access_token, verify_access_token


class FakeRedis:
    def __init__(self, raise_errors: bool = False):
        self._data: dict[str, str] = {}
        self._ttls: dict[str, int] = {}
        self.raise_errors = raise_errors

    async def set(self, name, value, ex=None):
        if self.raise_errors:
            raise RedisError("redis down")
        self._data[name] = value
        if ex is not None:
            self._ttls[name] = ex
        return True

    async def getdel(self, name):
        if self.raise_errors:
            raise RedisError("redis down")
        return self._data.pop(name, None)

    async def exists(self, name):
        if self.raise_errors:
            raise RedisError("redis down")
        return 1 if name in self._data else 0


def _keypair(user_id: str):
    private = Ed25519PrivateKey.generate()
    return {
        "user_id": user_id,
        "ik_public": private.public_key().public_bytes_raw(),
        "private": private,
    }


def _patch_redis(monkeypatch, fake: FakeRedis) -> None:
    async def _get_redis():
        return fake

    monkeypatch.setattr(auth_store, "get_redis", _get_redis)


def _patch_db(monkeypatch, user: dict | None) -> None:
    async def _get_user(user_id: str):
        return user

    monkeypatch.setattr(auth_service.db, "get_user", _get_user)


# ---------------------------------------------------------------------------
# create_challenge
# ---------------------------------------------------------------------------


async def test_create_challenge_unknown_user_raises_not_found(monkeypatch):
    _patch_db(monkeypatch, None)
    with pytest.raises(ResourceNotFound):
        await create_challenge("ghost")


async def test_create_challenge_issues_32_byte_nonce_with_ttl(monkeypatch):
    user = _keypair("alice")
    _patch_db(monkeypatch, user)
    fake = FakeRedis()
    _patch_redis(monkeypatch, fake)

    nonce = await create_challenge("alice")
    assert len(nonce) == 64 and len(bytes.fromhex(nonce)) == 32
    assert fake._data["auth_challenge:alice"] == nonce
    assert fake._ttls["auth_challenge:alice"] == settings.auth_challenge_ttl_seconds


async def test_challenge_redis_failure_fails_closed(monkeypatch):
    _patch_db(monkeypatch, _keypair("alice"))
    _patch_redis(monkeypatch, FakeRedis(raise_errors=True))
    with pytest.raises(RedisError):
        await create_challenge("alice")


# ---------------------------------------------------------------------------
# verify_credentials
# ---------------------------------------------------------------------------


async def _verify_success(monkeypatch, fake: FakeRedis, user: dict) -> tuple[str, str]:
    _patch_db(monkeypatch, user)
    _patch_redis(monkeypatch, fake)
    nonce = await create_challenge(user["user_id"])
    signature = user["private"].sign(bytes.fromhex(nonce)).hex()
    token = await verify_credentials(user["user_id"], nonce, signature)
    return token, nonce


async def test_valid_ed25519_signature_issues_token(monkeypatch):
    user = _keypair("alice")
    fake = FakeRedis()
    token, _ = await _verify_success(monkeypatch, fake, user)
    claims = verify_access_token(token)
    assert claims["sub"] == "alice"
    assert "jti" in claims
    assert len(claims) >= 6


async def test_valid_verification_consumes_challenge(monkeypatch):
    user = _keypair("alice")
    fake = FakeRedis()
    _, nonce = await _verify_success(monkeypatch, fake, user)
    assert "auth_challenge:alice" not in fake._data


async def test_invalid_signature_rejected(monkeypatch):
    user = _keypair("alice")
    _patch_db(monkeypatch, user)
    fake = FakeRedis()
    _patch_redis(monkeypatch, fake)
    nonce = await create_challenge(user["user_id"])

    wrong_signature = user["private"].sign(b"\x00" * 32).hex()
    with pytest.raises(HTTPException) as excinfo:
        await verify_credentials(user["user_id"], nonce, wrong_signature)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Authentication failed"


async def test_unknown_user_rejected_generically(monkeypatch):
    _patch_db(monkeypatch, None)
    _patch_redis(monkeypatch, FakeRedis())
    with pytest.raises(HTTPException) as excinfo:
        await verify_credentials("ghost", "aa" * 32, "bb" * 64)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Authentication failed"


@pytest.mark.parametrize(
    "nonce_hex, signature_hex",
    [
        ("zz" * 32, "ab" * 64),        # nonce not hex
        ("ab" * 32, "zz" * 64),        # signature not hex
        ("ab" * 24, "ab" * 64),        # nonce wrong length (48 hex -> 24 bytes)
        ("ab" * 32, "ab" * 48),        # signature wrong length (96 hex -> 48 bytes)
    ],
)
async def test_malformed_nonce_or_signature_rejected(monkeypatch, nonce_hex, signature_hex):
    _patch_db(monkeypatch, _keypair("alice"))
    _patch_redis(monkeypatch, FakeRedis())
    with pytest.raises(HTTPException) as excinfo:
        await verify_credentials("alice", nonce_hex, signature_hex)
    assert excinfo.value.status_code == 401


async def test_missing_challenge_rejected(monkeypatch):
    user = _keypair("alice")
    _patch_db(monkeypatch, user)
    _patch_redis(monkeypatch, FakeRedis())  # no challenge was issued
    signature = user["private"].sign(b"\x00" * 32).hex()
    with pytest.raises(HTTPException) as excinfo:
        await verify_credentials(user["user_id"], "aa" * 32, signature)
    assert excinfo.value.status_code == 401


async def test_replay_of_consumed_challenge_rejected(monkeypatch):
    user = _keypair("alice")
    _patch_db(monkeypatch, user)
    fake = FakeRedis()
    _patch_redis(monkeypatch, fake)

    nonce = await create_challenge(user["user_id"])
    signature = user["private"].sign(bytes.fromhex(nonce)).hex()

    assert await verify_credentials(user["user_id"], nonce, signature)
    # Same nonce + signature: the challenge is already consumed -> replay fails.
    with pytest.raises(HTTPException) as excinfo:
        await verify_credentials(user["user_id"], nonce, signature)
    assert excinfo.value.status_code == 401


async def test_verify_redis_failure_fails_closed(monkeypatch):
    user = _keypair("alice")
    _patch_db(monkeypatch, user)
    _patch_redis(monkeypatch, FakeRedis(raise_errors=True))
    with pytest.raises(RedisError):
        await verify_credentials(user["user_id"], "aa" * 32, "bb" * 64)


# ---------------------------------------------------------------------------
# development_login
# ---------------------------------------------------------------------------


async def test_development_login_issues_token(monkeypatch):
    _patch_db(monkeypatch, _keypair("alice"))
    _patch_redis(monkeypatch, FakeRedis())
    token = await development_login("alice")
    assert verify_access_token(token)["sub"] == "alice"


async def test_development_login_unknown_user_raises_not_found(monkeypatch):
    _patch_db(monkeypatch, None)
    with pytest.raises(ResourceNotFound):
        await development_login("ghost")


# ---------------------------------------------------------------------------
# Revocation (logout)
# ---------------------------------------------------------------------------


async def test_revoke_token_bounds_ttl_by_token_lifetime(monkeypatch):
    fake = FakeRedis()
    _patch_redis(monkeypatch, fake)
    claims = verify_access_token(create_access_token("alice"))
    await revoke_token(claims)
    jti = claims["jti"]
    ttl = fake._ttls[f"auth_revoked:{jti}"]
    assert 1 <= ttl <= settings.jwt_expiry_hours * 3600


# ---------------------------------------------------------------------------
# require_auth dependency
# ---------------------------------------------------------------------------


async def test_require_auth_returns_claims_for_valid_token(monkeypatch):
    _patch_redis(monkeypatch, FakeRedis())
    token = create_access_token("alice")
    claims = await require_auth(_BearerFake(token))
    assert claims["user_id"] == "alice"
    assert claims["jti"]


async def test_require_auth_rejects_revoked_token(monkeypatch):
    fake = FakeRedis()
    _patch_redis(monkeypatch, fake)
    token = create_access_token("alice")
    claims = verify_access_token(token)
    await revoke_token(claims)
    with pytest.raises(HTTPException) as excinfo:
        await require_auth(_BearerFake(token))
    assert excinfo.value.status_code == 401


async def test_require_auth_missing_credentials():
    with pytest.raises(HTTPException) as excinfo:
        await require_auth(None)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Missing bearer token"


async def test_require_auth_fails_closed_on_redis_error(monkeypatch):
    _patch_redis(monkeypatch, FakeRedis(raise_errors=True))
    with pytest.raises(RedisError):
        await require_auth(_BearerFake(create_access_token("alice")))


class _BearerFake:
    """Minimal stand-in for HTTPAuthorizationCredentials."""

    def __init__(self, credentials: str):
        self.credentials = credentials

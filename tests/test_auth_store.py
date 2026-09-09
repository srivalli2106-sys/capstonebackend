"""Redis auth-store tests with an in-memory fake (no running Redis).

Covers challenge issuance/binding/TTL, atomic single-use consumption (incl.
concurrency), bounded revocation entries, and fail-closed behaviour when
Redis raises.
"""

from __future__ import annotations

import asyncio

import pytest
from redis.exceptions import RedisError

from server import auth_store
from server.auth_store import (
    consume_challenge,
    is_token_revoked,
    issue_challenge,
    revoke_token,
)
from server.config import settings


class FakeRedis:
    """In-memory stand-in for the auth-store Redis surface (getdel-based)."""

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

    async def get(self, name):
        if self.raise_errors:
            raise RedisError("redis down")
        return self._data.get(name)

    async def getdel(self, name):
        if self.raise_errors:
            raise RedisError("redis down")
        return self._data.pop(name, None)

    async def exists(self, name):
        if self.raise_errors:
            raise RedisError("redis down")
        return 1 if name in self._data else 0


class FakeRedisOld:
    """Pre-GETDEL fallback surface: only SET/GET/DELETEvia EVAL (Lua)."""

    def __init__(self):
        self._data: dict[str, str] = {}

    async def set(self, name, value, ex=None):
        self._data[name] = value
        return True

    async def eval(self, script, numkeys, *keys_and_args):
        key, nonce = keys_and_args[0], keys_and_args[1]
        if self._data.get(key) == nonce:
            self._data.pop(key, None)
            return 1
        return 0


@pytest.fixture
def fake_redis(monkeypatch) -> FakeRedis:
    fake = FakeRedis()

    async def _get_redis():
        return fake

    monkeypatch.setattr(auth_store, "get_redis", _get_redis)
    return fake


# ---------------------------------------------------------------------------
# Challenge issuance
# ---------------------------------------------------------------------------

CHALLENGE_KEY = "auth_challenge:alice"


async def test_issue_challenge_returns_32_byte_hex_nonce(fake_redis):
    nonce = await issue_challenge("alice", 120)
    assert len(nonce) == 64
    assert bytes.fromhex(nonce)  # valid hex
    assert len(bytes.fromhex(nonce)) == 32


async def test_issue_challenge_stores_bounded_ttl(fake_redis):
    await issue_challenge("alice", 120)
    assert fake_redis._data.get(CHALLENGE_KEY)
    assert fake_redis._ttls[CHALLENGE_KEY] == 120


async def test_issue_challenge_binds_to_user(fake_redis):
    await issue_challenge("alice", 120)
    await issue_challenge("bob", 120)
    assert "auth_challenge:alice" in fake_redis._data
    assert "auth_challenge:bob" in fake_redis._data


# ---------------------------------------------------------------------------
# Atomic single-use consumption
# ---------------------------------------------------------------------------


async def test_consume_correct_nonce_succeeds(fake_redis):
    nonce = await issue_challenge("alice", 120)
    assert await consume_challenge("alice", nonce) is True
    assert CHALLENGE_KEY not in fake_redis._data


async def test_consume_wrong_nonce_fails(fake_redis):
    await issue_challenge("alice", 120)
    assert await consume_challenge("alice", "ff" * 32) is False


async def test_consume_missing_challenge_fails(fake_redis):
    assert await consume_challenge("alice", "aa" * 32) is False


async def test_replay_of_consumed_challenge_fails(fake_redis):
    nonce = await issue_challenge("alice", 120)
    assert await consume_challenge("alice", nonce) is True
    assert await consume_challenge("alice", nonce) is False


async def test_concurrent_consume_has_single_winner(fake_redis):
    nonce = await issue_challenge("alice", 120)
    results = await asyncio.gather(
        *(consume_challenge("alice", nonce) for _ in range(8))
    )
    assert sum(results) == 1


async def test_consume_correct_nonce_succeeds_via_lua_fallback(monkeypatch):
    fake_old = FakeRedisOld()

    async def _get_redis():
        return fake_old

    monkeypatch.setattr(auth_store, "get_redis", _get_redis)

    nonce = await issue_challenge("alice", 120)
    assert await consume_challenge("alice", nonce) is True
    assert await consume_challenge("alice", nonce) is False


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


REVOKED_KEY = "auth_revoked:token-abc"


async def test_revoke_token_stores_bounded_ttl(fake_redis):
    await revoke_token("token-abc", 300)
    assert fake_redis._data[REVOKED_KEY] == "1"
    assert fake_redis._ttls[REVOKED_KEY] == 300


async def test_revoked_token_flagged(fake_redis):
    assert await is_token_revoked("token-abc") is False
    await revoke_token("token-abc", 300)
    assert await is_token_revoked("token-abc") is True


# ---------------------------------------------------------------------------
# Fail closed on Redis errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    [
        ("issue", lambda: issue_challenge("alice", 120)),
        ("consume", lambda: consume_challenge("alice", "aa" * 32)),
        ("revoked", lambda: is_token_revoked("x")),
    ],
)
async def test_redis_failure_propagates(monkeypatch, operation):
    async def _get_redis():
        return FakeRedis(raise_errors=True)

    monkeypatch.setattr(auth_store, "get_redis", _get_redis)
    with pytest.raises(RedisError):
        await operation[1]()


async def test_settings_ttl_is_positive():
    assert settings.auth_challenge_ttl_seconds >= 5

"""Redis client tests using fakes (no running Redis required).

Covers the connection-layer contract of :mod:`server.redis_client`:
* a single reused client built with bounded pooling/timeouts from settings
* ping for the startup connectivity check
* clean pool close on shutdown (and a safe no-op before first use)

Presence/queue persistence (online:/conn:/pending: keys) is covered in
:mod:`tests.test_repositories`.
"""

from __future__ import annotations

from server import redis_client as rc_module
from server.redis_client import close_redis, get_redis, ping_redis


class FakeRedisClient:
    def __init__(self):
        self.ping_calls = 0
        self.closed = False

    async def ping(self):
        self.ping_calls += 1
        return True

    async def aclose(self):
        self.closed = True


async def test_get_redis_creates_single_client_with_bounds(monkeypatch):
    created = {}
    fake = FakeRedisClient()

    def _fake_from_url(*args, **kwargs):
        created["args"] = args
        created["kwargs"] = kwargs
        return fake

    monkeypatch.setattr(rc_module.aioredis, "from_url", _fake_from_url)
    monkeypatch.setattr(rc_module, "_pool", None)

    first = await get_redis()
    second = await get_redis()

    assert first is second is fake
    assert created["args"][0] == rc_module.REDIS_URL
    opts = created["kwargs"]
    assert opts["decode_responses"] is True
    assert opts["max_connections"] == rc_module.settings.redis_max_connections
    assert (
        opts["socket_connect_timeout"]
        == rc_module.settings.redis_socket_connect_timeout
    )
    assert opts["socket_timeout"] == rc_module.settings.redis_socket_timeout
    assert (
        opts["health_check_interval"] == rc_module.settings.redis_health_check_interval
    )


async def test_ping_redis(monkeypatch):
    fake = FakeRedisClient()
    monkeypatch.setattr(rc_module, "_pool", fake)

    assert await ping_redis() is True
    assert fake.ping_calls == 1


async def test_close_redis_closes_and_resets_pool(monkeypatch):
    fake = FakeRedisClient()
    monkeypatch.setattr(rc_module, "_pool", fake)

    await close_redis()
    assert fake.closed is True
    assert rc_module._pool is None


async def test_close_redis_is_noop_when_never_initialized(monkeypatch):
    monkeypatch.setattr(rc_module, "_pool", None)
    await close_redis()  # must not raise

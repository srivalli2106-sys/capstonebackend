"""Rate limit logic tests using a fake Redis pipeline (no Redis needed)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException, Request

from server import middleware
from server.middleware import RATE_LIMITS, check_rate_limit


class FakePipeline:
    """Minimal stand-in for redis' pipeline object (sliding-window calls)."""

    def __init__(self, count: int):
        self.ops: list[tuple] = []
        self.count = count

    def zremrangebyscore(self, *args):
        self.ops.append(("zremrangebyscore", args))
        return self

    def zadd(self, *args):
        self.ops.append(("zadd", args))

    def zcard(self, *args):
        self.ops.append(("zcard", args))
        return self.count

    def expire(self, *args):
        self.ops.append(("expire", args))
        return self

    async def execute(self):
        return [1, 1, self.count, 60]


class FakeRedis:
    def __init__(self, count: int):
        self._count = count
        self.last_pipeline: FakePipeline | None = None

    def pipeline(self):
        self.last_pipeline = FakePipeline(self._count)
        return self.last_pipeline


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "client": ("10.0.0.1", 1234)})


@pytest.mark.parametrize(
    "category,expected",
    [
        ("register", (1, 3600)),
        ("login", (10, 60)),
        ("challenge", (10, 60)),
        ("verify", (20, 60)),
        ("logout", (30, 60)),
        ("keys", (30, 60)),
        ("general", (100, 60)),
        ("unknown-category", (100, 60)),  # falls back to "general"
    ],
)
def test_rate_limit_configuration(category, expected):
    assert RATE_LIMITS.get(category, RATE_LIMITS["general"]) == expected


def _patch_redis(monkeypatch: pytest.MonkeyPatch, fake: FakeRedis) -> None:
    """Make server.middleware.get_redis return `fake` (it is awaited)."""

    async def _get_redis():
        return fake

    monkeypatch.setattr(middleware, "get_redis", _get_redis)


async def test_under_limit_passes(monkeypatch):
    _patch_redis(monkeypatch, FakeRedis(count=1))
    await check_rate_limit(_request())  # should not raise


async def test_over_limit_raises_429(monkeypatch):
    _patch_redis(monkeypatch, FakeRedis(count=101))
    with pytest.raises(HTTPException) as excinfo:
        await check_rate_limit(_request(), "general")
    assert excinfo.value.status_code == 429


async def test_pipeline_compile_sequence(monkeypatch):
    fake = FakeRedis(count=1)
    _patch_redis(monkeypatch, fake)
    await check_rate_limit(_request(), "general")
    ops = [op[0] for op in fake.last_pipeline.ops]
    assert ops == ["zremrangebyscore", "zadd", "zcard", "expire"]

"""
redis_client.py — Redis connection lifecycle and low-level helpers.

Stores:
  online:{user_id}   — bool, whether user is currently connected
  pending:{user_id}  — list of queued messages for offline users
  sessions:{jwt_id}  — session metadata

All presence/queue read-write persistence lives in the repositories layer
(:mod:`server.repositories.presence_repository`,
:mod:`server.repositories.message_repository`); this module owns only the
shared pool, its bounds, health checks, and shutdown, plus the three
low-level session key helpers used nowhere else today.
"""

from __future__ import annotations

import redis.asyncio as aioredis

from .config import settings

REDIS_URL = settings.redis_url

_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(
            REDIS_URL,
            decode_responses=True,
            max_connections=settings.redis_max_connections,
            socket_connect_timeout=settings.redis_socket_connect_timeout,
            socket_timeout=settings.redis_socket_timeout,
            health_check_interval=settings.redis_health_check_interval,
        )
    return _pool


async def ping_redis() -> bool:
    r = await get_redis()
    await r.ping()
    return True


async def close_redis() -> None:
    """Close the shared client/pool so the event loop exits cleanly."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None


# ---------------------------------------------------------------------------
# Session tracking (low-level; no current caller)
# ---------------------------------------------------------------------------


async def store_session(user_id: str, token_id: str, ttl: int = 86400) -> None:
    r = await get_redis()
    await r.set(f"session:{token_id}", user_id, ex=ttl)


async def validate_session(token_id: str) -> str | None:
    r = await get_redis()
    return await r.get(f"session:{token_id}")


async def invalidate_session(token_id: str) -> None:
    r = await get_redis()
    await r.delete(f"session:{token_id}")

"""
redis_client.py — Redis connection and helpers.

Stores:
  online:{user_id}   — bool, whether user is currently connected
  pending:{user_id}  — list of queued messages for offline users
  sessions:{jwt_id}  — session metadata
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
# Online status
# ---------------------------------------------------------------------------


async def set_online(user_id: str) -> None:
    r = await get_redis()
    await r.set(f"online:{user_id}", "1", ex=settings.ws_presence_ttl_seconds)


async def is_online(user_id: str) -> bool:
    r = await get_redis()
    return await r.exists(f"online:{user_id}") > 0


async def set_offline(user_id: str) -> None:
    r = await get_redis()
    await r.delete(f"online:{user_id}")


# ---------------------------------------------------------------------------
# Pending message queue (for offline users)
# ---------------------------------------------------------------------------


async def enqueue_message(user_id: str, payload: str) -> None:
    r = await get_redis()
    await r.rpush(f"pending:{user_id}", payload)


async def dequeue_all_messages(user_id: str) -> list[str]:
    r = await get_redis()
    key = f"pending:{user_id}"
    msgs: list[str] = []
    while True:
        item = await r.lpop(key)
        if item is None:
            break
        msgs.append(item)
    return msgs


# ---------------------------------------------------------------------------
# Active connections (user_id -> websocket connection id)
# ---------------------------------------------------------------------------


async def register_connection(user_id: str, connection_id: str) -> None:
    r = await get_redis()
    await r.set(
        f"conn:{user_id}", connection_id, ex=settings.ws_presence_ttl_seconds
    )


async def get_connection(user_id: str) -> str | None:
    r = await get_redis()
    return await r.get(f"conn:{user_id}")


async def remove_connection(user_id: str) -> None:
    r = await get_redis()
    await r.delete(f"conn:{user_id}")


# ---------------------------------------------------------------------------
# Session tracking
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

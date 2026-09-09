"""presence_repository.py — Redis persistence for online/connection markers.

Owns the ``online:{user_id}`` and ``conn:{user_id}`` keys. Presence is
non-security state: callers decide how to degrade on Redis failure (see
:mod:`server.services.presence_service`); this layer only converts the
low-level Redis value into the small boolean/str application shape.
"""

from __future__ import annotations

from ..config import settings
from ..redis_client import get_redis


class PresenceRepository:
    """Persistence mechanics for presence markers (no business rules)."""

    async def set_online(self, user_id: str) -> None:
        r = await get_redis()
        await r.set(
            f"online:{user_id}", "1", ex=settings.ws_presence_ttl_seconds
        )

    async def is_online(self, user_id: str) -> bool:
        r = await get_redis()
        return await r.exists(f"online:{user_id}") > 0

    async def set_offline(self, user_id: str) -> None:
        r = await get_redis()
        await r.delete(f"online:{user_id}")

    async def register_connection(self, user_id: str, connection_id: str) -> None:
        r = await get_redis()
        await r.set(
            f"conn:{user_id}",
            connection_id,
            ex=settings.ws_presence_ttl_seconds,
        )

    async def get_connection(self, user_id: str) -> str | None:
        r = await get_redis()
        return await r.get(f"conn:{user_id}")

    async def remove_connection(self, user_id: str) -> None:
        r = await get_redis()
        await r.delete(f"conn:{user_id}")


presence_repository = PresenceRepository()

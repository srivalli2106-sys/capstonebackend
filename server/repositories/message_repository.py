"""message_repository.py — Redis persistence for the offline message queue.

Owns the ``pending:{user_id}`` list: appending a message for an offline user
and draining (LDELETE-all) on connect. The queue is opaque payload strings;
the repository never inspects message contents.
"""

from __future__ import annotations

from ..redis_client import get_redis


class MessageRepository:
    """Persistence mechanics for the offline queue (no business rules)."""

    async def enqueue_message(self, user_id: str, payload: str) -> None:
        r = await get_redis()
        await r.rpush(f"pending:{user_id}", payload)

    async def dequeue_all_messages(self, user_id: str) -> list[str]:
        r = await get_redis()
        key = f"pending:{user_id}"
        msgs: list[str] = []
        while True:
            item = await r.lpop(key)
            if item is None:
                break
            msgs.append(item)
        return msgs


message_repository = MessageRepository()

"""
ws_registry.py — process-local registry of active WebSocket connections.

Phase 7: a single server process tracks two things per websocket:

  * a global connection budget (``ws_max_connections``), reserved before the
    socket is accepted and released exactly once in the endpoint ``finally``;
  * a per-user mapping (``_by_user``) so a new connection for the same user
    can take over and replace the old one, and so the relay can look up a
    recipient's live socket without holding a module-global dict.

Every mutation takes the module's asyncio lock (the registry is shared by all
connections of the process). Connection identity is the ``conn_id``: removal
is guarded by it so a superseded connection's disconnect can never evict the
replacement connection.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from starlette.websockets import WebSocket

from .config import settings

logger = logging.getLogger(__name__)


@dataclass
class WsConnection:
    """Everything the relay needs to address one live connection."""

    conn_id: str
    user_id: str
    websocket: WebSocket
    claims: dict


class WsRegistry:
    def __init__(self, max_connections: int, max_connections_per_ip: int = 20) -> None:
        self._max_connections = max_connections
        self._max_per_ip = max_connections_per_ip
        self._reserved = 0
        self._by_user: dict[str, WsConnection] = {}
        self._by_ip: dict[str, int] = {}
        self._lock = asyncio.Lock()

    @property
    def max_connections(self) -> int:
        return self._max_connections

    @property
    def max_connections_per_ip(self) -> int:
        return self._max_per_ip

    async def try_reserve(self) -> bool:
        """Reserve a connection slot; False when the budget is exhausted."""
        async with self._lock:
            if self._reserved >= self._max_connections:
                return False
            self._reserved += 1
            return True

    async def release_slot(self) -> None:
        """Return a connection slot (idempotent, never goes negative)."""
        async with self._lock:
            if self._reserved > 0:
                self._reserved -= 1

    async def try_register_ip(self, ip: str) -> bool:
        """Account one connection to ``ip``; False when its cap is reached.

        ``max_connections_per_ip == 0`` disables the per-IP cap. Unknown peers
        (``client`` is None) are normalized to a sentinel key.
        """
        if self._max_per_ip <= 0:
            return True
        key = ip or "<unknown>"
        async with self._lock:
            count = self._by_ip.get(key, 0)
            if count >= self._max_per_ip:
                return False
            self._by_ip[key] = count + 1
            return True

    async def release_ip(self, ip: str) -> None:
        """Release one per-IP accounting unit (idempotent)."""
        key = ip or "<unknown>"
        async with self._lock:
            count = self._by_ip.get(key, 0)
            if count <= 1:
                self._by_ip.pop(key, None)
            else:
                self._by_ip[key] = count - 1

    async def register(
        self, user_id: str, conn: WsConnection
    ) -> WsConnection | None:
        """Register ``conn`` for ``user_id``; return any previous live one."""
        async with self._lock:
            old = self._by_user.get(user_id)
            self._by_user[user_id] = conn
            return old

    def get(self, user_id: str) -> WsConnection | None:
        return self._by_user.get(user_id)

    async def remove(self, user_id: str, conn_id: str) -> None:
        """Remove ``user_id`` only when its current conn_id matches."""
        async with self._lock:
            current = self._by_user.get(user_id)
            if current is not None and current.conn_id == conn_id:
                del self._by_user[user_id]

    async def close_all(
        self, code: int = 1001, reason: str = "Server shutting down"
    ) -> None:
        """Close every live connection (used during application shutdown)."""
        async with self._lock:
            conns = list(self._by_user.values())
            self._by_user.clear()
            self._by_ip.clear()
            self._reserved = 0
        if conns:
            await asyncio.gather(
                *(
                    close_websocket(conn.websocket, code, reason)
                    for conn in conns
                ),
                return_exceptions=True,
            )


# Shared by every WebSocket endpoint in this process.
registry = WsRegistry(
    settings.ws_max_connections,
    max_connections_per_ip=settings.ws_max_connections_per_ip,
)


async def close_websocket(
    ws: WebSocket, code: int, reason: str | None = None
) -> None:
    """Best-effort close: a closed/broken transport is never an error."""
    try:
        await ws.close(code=code, reason=reason or "")
    except Exception:
        logger.debug("websocket already closed; ignoring close attempt")

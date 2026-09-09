"""presence_service.py — presence lifecycle decisions (degrading by design).

Owns how the WebSocket endpoint marks a user online/offline and keeps the
presence/connection markers alive. Presence is non-security state (Phase 4
policy): Redis failures here are logged and ignored so an operational blip
never prevents a valid connection from being established or torn down. This
must never be conflated with authentication/revocation, which stays fail
closed in :mod:`server.ws_auth`.
"""

from __future__ import annotations

import logging
from asyncio import sleep as _sleep

from ..config import settings
from ..repositories.presence_repository import presence_repository
from ..repositories.protocols import PresenceRepository

logger = logging.getLogger(__name__)


class PresenceService:
    """Decisions around online/connection markers (no persistence logic)."""

    def __init__(self, presence: PresenceRepository | None = None) -> None:
        self._presence = presence or presence_repository

    async def connect(self, user_id: str, conn_id: str) -> None:
        """Mark the user online for the new connection (best effort).

        Each Redis write is individually guarded so a failure on one never
        prevents the other from being attempted.
        """
        try:
            await self._presence.set_online(user_id)
        except Exception:
            logger.warning("redis presence unavailable for %s at connect", user_id)
        try:
            await self._presence.register_connection(user_id, conn_id)
        except Exception:
            logger.warning("redis connection registration unavailable for %s", user_id)

    async def clear(self, user_id: str) -> None:
        """Clear the user's presence + connection markers (best effort)."""
        for label, cleanup in (
            ("set_offline", self._presence.set_offline),
            ("remove_connection", self._presence.remove_connection),
        ):
            try:
                await cleanup(user_id)
            except Exception:
                logger.warning(
                    "redis unavailable during %s cleanup for %s", label, user_id
                )

    async def keep_alive(
        self,
        user_id: str,
        conn_id: str,
        current_conn_id,
        interval: int | None = None,
    ) -> None:
        """Refresh presence every half-TTL while ``conn_id`` is current.

        ``current_conn_id(user_id)`` returns the registered connection id (or
        None); the loop stops as soon as this connection was superseded or
        disconnected. Fails gracefully on Redis errors — the marker simply
        expires, indistinguishable from going offline.
        """
        sleep_interval = (
            interval if interval is not None else settings.ws_presence_ttl_seconds // 2
        )
        while True:
            await _sleep(sleep_interval)
            if current_conn_id(user_id) != conn_id:
                return
            try:
                await self._presence.set_online(user_id)
                await self._presence.register_connection(user_id, conn_id)
            except Exception:
                logger.warning("presence refresh failed for %s", user_id)


presence_service = PresenceService()

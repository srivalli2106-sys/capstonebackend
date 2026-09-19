"""
presence.py — Presence endpoint (Messaging UX phase).

Minimal read-only online/offline presence backed by the existing Redis
markers. ``GET /presence/{user_id}`` requires an authenticated token and is
rate-limited (see ``middleware.RATE_LIMITS["presence"]``).

The ``online`` flag reflects whether the peer currently holds a live,
authenticated WebSocket connection (its connection marker is {user_id}). It
deliberately exposes no last-seen timestamp, no device/IP metadata, and
nothing derived from the peer's message content. Presence is non-security,
ephemeral state; when Redis is unavailable the peer is reported offline
instead of leaking a storage error.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..middleware import check_rate_limit, require_auth
from ..repositories.presence_repository import presence_repository

router = APIRouter(prefix="/presence", tags=["presence"])


async def _resolve_online(user_id: str) -> bool:
    """Return the peer's online state, degrading to offline on storage errors."""
    try:
        return await presence_repository.is_online(user_id)
    except Exception:
        # Presence is non-security state: prefer an honest "offline" answer
        # over surfacing a Redis failure body to the caller.
        return False


@router.get("/{target_user_id}")
async def get_presence(
    target_user_id: str,
    request: Request,
    auth: dict = Depends(require_auth),
) -> dict:
    await check_rate_limit(request, "presence")
    online = await _resolve_online(target_user_id)
    return {"user_id": target_user_id, "online": online}

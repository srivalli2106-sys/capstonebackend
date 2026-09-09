"""
messages.py — WebSocket relay for encrypted message delivery (Phase 7).

Handshake (no query-string token):
  1. Client connects to /ws and sends, as its FIRST frame:
     {"type": "auth", "token": "<JWT>"}
  2. Server validates the token (signature/algorithm/issuer/expiry + Redis
     revocation, fail closed) and marks the user online.
  3. Client then sends: {"to": "<user_id>", "data": "<base64 payload>"}
  4. Server forwards to recipient if online, else queues in Redis.
  5. On connect, the server flushes any pending queued messages.

Connection lifecycle is enforced by :mod:`server.ws_registry` (per-process
budget + per-user takeover) and :mod:`server.ws_auth` (auth timeout, token
expiry/revocation watcher, connect/message rate gates).

This route is a thin transport adapter: frame I/O, validation, auth, and
lifecycle/cleanup stay here; business decisions are delegated to
:mod:`server.services.message_service` (deliver/queue/flush) and
:mod:`server.services.presence_service` (online/offline markers + keep-alive).

All message bodies are opaque encrypted blobs — server never sees plaintext.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import ws_auth, ws_registry
from ..services.message_service import MAX_WS_MESSAGE_CHARS, message_service
from ..services.presence_service import presence_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["messages"])


def _current_conn_id(user_id: str) -> str | None:
    """Registered connection id for ``user_id`` (None when offline)."""
    conn = ws_registry.registry.get(user_id)
    return conn.conn_id if conn is not None else None


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    conn_id = ws_auth.new_connection_id()
    client_ip = ws.client.host if ws.client else "unknown"
    tasks: list[asyncio.Task] = []
    slot_reserved = False
    registered = False
    user_id: str | None = None

    try:
        # Connection budget: refuse BEFORE accepting when at capacity. The
        # slot is released exactly once in the finally block.
        if not await ws_registry.registry.try_reserve():
            await ws_registry.close_websocket(
                ws, ws_auth.WS_CAPACITY, ws_auth.REASON_CAPACITY
            )
            return
        slot_reserved = True

        if not await ws_auth.allow_ws_connect(client_ip):
            await ws_registry.close_websocket(
                ws, ws_auth.WS_CAPACITY, ws_auth.REASON_RATE_LIMITED
            )
            return

        await ws.accept()

        # First-frame authentication (with timeout). None == peer left during
        # the handshake; WsAuthError == refused (close code from the error).
        token = await ws_auth.receive_auth_token(ws)
        if token is None:
            return
        claims = await ws_auth.verify_ws_token(token)
        user_id = claims["sub"]

        conn = ws_registry.WsConnection(
            conn_id=conn_id, user_id=user_id, websocket=ws, claims=claims
        )
        old = await ws_registry.registry.register(user_id, conn)
        registered = True
        if old is not None:
            # Takeover: one live connection per user per process.
            await ws_registry.close_websocket(
                old.websocket, ws_auth.WS_REPLACED, ws_auth.REASON_REPLACED
            )

        # Redis presence is best-effort: an unavailable Redis must not prevent
        # a valid user from connecting, so failures are logged and we continue.
        await presence_service.connect(user_id, conn_id)

        logger.info("[WS] %s connected conn_id=%s", user_id, conn_id)

        # Flush any pending messages that arrived while offline.
        await message_service.flush_pending(user_id, ws)

        # Background guards: token lifetime (expiry/revocation) and presence
        # keep-alive. Both are cancelled on disconnect in the finally block.
        tasks.append(ws_auth.close_on_token_expiry(ws, claims))
        tasks.append(
            asyncio.create_task(
                presence_service.keep_alive(user_id, conn_id, _current_conn_id)
            )
        )

        while True:
            event = await ws_auth.receive_ws_event(ws)
            if event is None:
                break
            kind, value = event
            if kind == "disconnect":
                break
            if kind == "bytes":
                # Binary frames are unsupported; drop without closing.
                continue
            raw = value
            if not isinstance(raw, str):
                continue
            if len(raw) > MAX_WS_MESSAGE_CHARS:
                await ws_registry.close_websocket(
                    ws, ws_auth.WS_TOO_LARGE, ws_auth.REASON_TOO_LARGE
                )
                break
            if not await ws_auth.allow_ws_message(user_id):
                # Rate limited: drop the frame, keep the connection alive.
                continue
            await message_service.handle_message(user_id, raw)

    except ws_auth.WsAuthError as exc:
        await ws_registry.close_websocket(ws, exc.code, exc.reason)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("unexpected websocket error for conn_id=%s", conn_id)
    finally:
        # Stop background guards first so their Redis work cannot interleave
        # with teardown below (all errors are suppressed: teardown is
        # best-effort and must never mask the original cause).
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if registered:
            # conn_id guard: a replacement connection (another tab/device) is
            # never evicted by this disconnect.
            await ws_registry.registry.remove(user_id, conn_id)
            # Only clear presence when no live connection remains for the user.
            if ws_registry.registry.get(user_id) is None:
                await presence_service.clear(user_id)

        if slot_reserved:
            await ws_registry.registry.release_slot()
        logger.info("[WS] disconnected conn_id=%s user_id=%s", conn_id, user_id)

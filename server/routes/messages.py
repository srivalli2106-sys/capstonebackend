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
expiry/revocation watcher, connect/message rate gates). Presence and pending
messages live in Redis and degrade gracefully on Redis failures.

All message bodies are opaque encrypted blobs — server never sees plaintext.
"""

from __future__ import annotations

import asyncio
import json
import logging
from asyncio import sleep as _sleep

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import ws_auth, ws_registry
from ..config import settings
from ..redis_client import (
    dequeue_all_messages,
    enqueue_message,
    is_online,
    register_connection,
    remove_connection,
    set_offline,
    set_online,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["messages"])

# Input bounds (Phase 5). The whole JSON frame and the recipient id are
# bounded to keep Redis keys and forwarded frames from growing unboundedly.
# These are protocol inputs only: message contents are never inspected.
_MAX_WS_MESSAGE_CHARS = 65536
_MAX_TO_LENGTH = 64


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
        try:
            await set_online(user_id)
        except Exception:
            logger.warning("redis presence unavailable for %s at connect", user_id)
        try:
            await register_connection(user_id, conn_id)
        except Exception:
            logger.warning("redis connection registration unavailable for %s", user_id)

        logger.info("[WS] %s connected conn_id=%s", user_id, conn_id)

        # Flush any pending messages that arrived while offline.
        try:
            pending = await dequeue_all_messages(user_id)
        except Exception:
            logger.warning(
                "redis unavailable: could not flush queued messages for %s",
                user_id,
            )
            pending = []
        for msg in pending:
            try:
                await ws.send_text(msg)
                logger.info("[WS] Flushed pending message to %s", user_id)
            except Exception:
                try:
                    await enqueue_message(user_id, msg)
                except Exception:
                    logger.error(
                        "redis unavailable: failed to re-queue pending message "
                        "for %s",
                        user_id,
                    )
                break

        # Background guards: token lifetime (expiry/revocation) and presence
        # keep-alive. Both are cancelled on disconnect in the finally block.
        tasks.append(ws_auth.close_on_token_expiry(ws, claims))
        tasks.append(asyncio.create_task(_refresh_presence(user_id, conn_id)))

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
            if len(raw) > _MAX_WS_MESSAGE_CHARS:
                await ws_registry.close_websocket(
                    ws, ws_auth.WS_TOO_LARGE, ws_auth.REASON_TOO_LARGE
                )
                break
            if not await ws_auth.allow_ws_message(user_id):
                # Rate limited: drop the frame, keep the connection alive.
                continue
            await _handle_message(user_id, raw)

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
                for label, cleanup in (
                    ("set_offline", set_offline),
                    ("remove_connection", remove_connection),
                ):
                    try:
                        await cleanup(user_id)
                    except Exception:
                        logger.warning(
                            "redis unavailable during %s cleanup for %s",
                            label,
                            user_id,
                        )

        if slot_reserved:
            await ws_registry.registry.release_slot()
        logger.info("[WS] disconnected conn_id=%s user_id=%s", conn_id, user_id)


# ---------------------------------------------------------------------------
# Presence keep-alive
# ---------------------------------------------------------------------------


async def _refresh_presence(user_id: str, conn_id: str) -> None:
    """Refresh the Redis presence/connection TTL every half-life.

    Stops when this connection is no longer the registered one (superseded
    or disconnected). Fails gracefully on Redis errors — the marker simply
    expires, which is indistinguishable from going offline.
    """
    interval = settings.ws_presence_ttl_seconds // 2
    while True:
        await _sleep(interval)
        current = ws_registry.registry.get(user_id)
        if current is None or current.conn_id != conn_id:
            return
        try:
            await set_online(user_id)
            await register_connection(user_id, conn_id)
        except Exception:
            logger.warning("presence refresh failed for %s", user_id)


# ---------------------------------------------------------------------------
# Message handler
# ---------------------------------------------------------------------------


async def _handle_message(sender_id: str, raw: str) -> None:
    # Bound the frame before parsing so oversized input never reaches the
    # journal/presence/delivery code. Logged without any payload content.
    if len(raw) > _MAX_WS_MESSAGE_CHARS:
        logger.warning("dropping oversized websocket message from %s", sender_id)
        return

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    recipient_id = msg.get("to")
    data = msg.get("data")

    if not recipient_id or not data:
        return
    if not isinstance(recipient_id, str) or len(recipient_id) > _MAX_TO_LENGTH:
        logger.warning("dropping message with invalid recipient from %s", sender_id)
        return

    # Build the payload to forward (server never decrypts)
    forward = json.dumps({
        "from": sender_id,
        "data": data,
    })

    # Presence failures degrade gracefully: if we cannot read presence we
    # treat the recipient as offline and fall through to the queue path.
    try:
        online = await is_online(recipient_id)
    except Exception:
        online = False
        logger.warning(
            "presence lookup failed for %s; treating as offline", recipient_id
        )

    if online:
        conn = ws_registry.registry.get(recipient_id)
        if conn is not None:
            try:
                await conn.websocket.send_text(forward)
                logger.info("[WS] Forwarded message %s -> %s", sender_id, recipient_id)
                return
            except Exception:
                pass

    # Recipient offline — queue the message. If the Redis write fails we
    # must never claim the message was queued: report it explicitly, stop,
    # and leave the sender's connection alive.
    try:
        await enqueue_message(recipient_id, forward)
    except Exception:
        logger.error(
            "redis unavailable: message from %s to %s was NOT queued",
            sender_id,
            recipient_id,
        )
        return
    logger.info("[WS] Queued message for offline user %s", recipient_id)

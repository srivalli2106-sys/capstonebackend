"""
messages.py — WebSocket relay for encrypted message delivery.

Protocol:
  1. Client connects to /ws with JWT in query param
  2. Server marks user online
  3. Client sends: {"to": "<user_id>", "data": "<base64 payload>"}
  4. Server forwards to recipient if online, else queues in Redis
  5. On connect, server flushes any pending queued messages

All message bodies are opaque encrypted blobs — server never sees plaintext.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ..middleware import decode_token
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

# In-memory map of user_id -> WebSocket (for single-server deployment)
_connections: dict[str, WebSocket] = {}


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws")
async def websocket_endpoint(
    ws: WebSocket,
    token: str = Query(...),
):
    # Authenticate via JWT query param
    try:
        payload = decode_token(token)
    except Exception:
        await ws.close(code=4001, reason="Invalid token")
        return

    user_id: str = payload["user_id"]

    await ws.accept()

    # Check for existing connection and close it
    old = _connections.get(user_id)
    if old is not None:
        try:
            await old.close(code=4000, reason="Replaced by new connection")
        except Exception:
            pass

    _connections[user_id] = ws
    await set_online(user_id)
    await register_connection(user_id, user_id)

    logger.info(f"[WS] {user_id} connected")

    # Flush any pending messages that arrived while offline
    pending = await dequeue_all_messages(user_id)
    for msg in pending:
        try:
            await ws.send_text(msg)
            logger.info(f"[WS] Flushed pending message to {user_id}")
        except Exception:
            await enqueue_message(user_id, msg)
            break

    try:
        while True:
            raw = await ws.receive_text()
            await _handle_message(user_id, raw)
    except WebSocketDisconnect:
        logger.info(f"[WS] {user_id} disconnected")
    except Exception as e:
        logger.error(f"[WS] Error for {user_id}: {e}")
    finally:
        _connections.pop(user_id, None)
        await set_offline(user_id)
        await remove_connection(user_id)


# ---------------------------------------------------------------------------
# Message handler
# ---------------------------------------------------------------------------


async def _handle_message(sender_id: str, raw: str) -> None:
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    recipient_id = msg.get("to")
    data = msg.get("data")

    if not recipient_id or not data:
        return

    # Build the payload to forward (server never decrypts)
    forward = json.dumps({
        "from": sender_id,
        "data": data,
    })

    if await is_online(recipient_id):
        ws = _connections.get(recipient_id)
        if ws is not None:
            try:
                await ws.send_text(forward)
                logger.info(f"[WS] Forwarded message {sender_id} -> {recipient_id}")
                return
            except Exception:
                pass

    # Recipient offline — queue the message
    await enqueue_message(recipient_id, forward)
    logger.info(f"[WS] Queued message for offline user {recipient_id}")

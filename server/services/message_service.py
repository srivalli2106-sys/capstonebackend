"""message_service.py — message delivery/queue business decisions.

Owns everything the WebSocket relay does with one inbound message frame:

  * bounding/validating the frame and the recipient (before any Redis work),
  * deciding whether the recipient is reachable right now (presence read that
    degrades to "offline" on Redis failure),
  * forwarding to the live socket when reachable, else queueing,
  * the queue-failure contract: a failed queue write is never claimed as
    queued,
  * flushing the pending queue when a user connects.

The recipient's live connection is resolved through an injected lookup
callback (defaulting to the process-local :mod:`server.ws_registry`) so unit
tests can substitute a plain mapping. Payloads are opaque encrypted blobs;
the service never inspects message content and never logs it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

from .. import ws_registry
from ..repositories.message_repository import message_repository
from ..repositories.presence_repository import presence_repository
from ..repositories.protocols import MessageRepository, PresenceRepository

logger = logging.getLogger(__name__)

# Input bounds (Phase 5). The whole JSON frame and the recipient id are
# bounded to keep Redis keys and forwarded frames from growing unboundedly.
# These are protocol inputs only: message contents are never inspected.
MAX_WS_MESSAGE_CHARS = 65536
MAX_TO_LENGTH = 64


def _default_registry_lookup(user_id: str):
    """Resolve the recipient's live connection from the process registry."""
    return ws_registry.registry.get(user_id)


class MessageService:
    """Delivery/queue decisions for one encrypted message (no persistence)."""

    def __init__(
        self,
        messages: MessageRepository | None = None,
        presence: PresenceRepository | None = None,
        registry_lookup: Callable[[str], object] | None = None,
    ) -> None:
        self._messages = messages or message_repository
        self._presence = presence or presence_repository
        # Resolved at call time (module attribute) so tests can swap the
        # process registry after construction.
        self._lookup = registry_lookup or _default_registry_lookup

    async def handle_message(self, sender_id: str, raw: str) -> None:
        """Process one inbound frame: forward, queue, or drop. Never raises."""
        # Bound the frame before parsing so oversized input never reaches the
        # journal/presence/delivery code. Logged without any payload content.
        if len(raw) > MAX_WS_MESSAGE_CHARS:
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
        if not isinstance(recipient_id, str) or len(recipient_id) > MAX_TO_LENGTH:
            logger.warning("dropping message with invalid recipient from %s", sender_id)
            return

        # Build the payload to forward (server never decrypts)
        forward = json.dumps({"from": sender_id, "data": data})

        # Presence failures degrade gracefully: if we cannot read presence we
        # treat the recipient as offline and fall through to the queue path.
        try:
            online = await self._presence.is_online(recipient_id)
        except Exception:
            online = False
            logger.warning(
                "presence lookup failed for %s; treating as offline", recipient_id
            )

        if online:
            conn = self._lookup(recipient_id)
            if conn is not None:
                try:
                    await conn.websocket.send_text(forward)
                    logger.info(
                        "[WS] Forwarded message %s -> %s", sender_id, recipient_id
                    )
                    return
                except Exception:
                    pass

        # Recipient offline — queue the message. If the Redis write fails we
        # must never claim the message was queued: report it explicitly and
        # leave the sender's connection alive.
        try:
            await self._messages.enqueue_message(recipient_id, forward)
        except Exception:
            logger.error(
                "redis unavailable: message from %s to %s was NOT queued",
                sender_id,
                recipient_id,
            )
            return
        logger.info("[WS] Queued message for offline user %s", recipient_id)

    async def flush_pending(self, user_id: str, sender) -> None:
        """Flush all queued messages to ``sender`` on connect (best effort).

        If a send fails, the message is re-queued (when possible) and the
        flush stops so remaining messages stay queued in order.
        """
        try:
            pending = await self._messages.dequeue_all_messages(user_id)
        except Exception:
            logger.warning(
                "redis unavailable: could not flush queued messages for %s", user_id
            )
            return
        for msg in pending:
            try:
                await sender.send_text(msg)
                logger.info("[WS] Flushed pending message to %s", user_id)
            except Exception:
                try:
                    await self._messages.enqueue_message(user_id, msg)
                except Exception:
                    logger.error(
                        "redis unavailable: failed to re-queue pending message "
                        "for %s",
                        user_id,
                    )
                break


message_service = MessageService()

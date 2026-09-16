"""message_service.py — message delivery/queue business decisions.

Owns everything the WebSocket relay does with one inbound message frame:

  * validating the frame and building the server-authoritative envelope
    (see :mod:`server.envelope`) before any Redis work,
  * replay protection: an envelope id seen within the dedup window is dropped,
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
import time
from collections.abc import Callable

from .. import ws_registry
from ..envelope import DEDUP_TTL_SECONDS, normalize_envelope
from ..repositories.message_repository import message_repository
from ..repositories.presence_repository import presence_repository
from ..repositories.protocols import MessageRepository, PresenceRepository

logger = logging.getLogger(__name__)

# Input bounds (Phase 5). The whole JSON frame is bounded to keep Redis keys
# and forwarded frames from growing unboundedly. The envelope payload itself
# is bounded by envelope.MAX_DATA_CHARS. These are protocol inputs only:
# message contents are never inspected.
MAX_WS_MESSAGE_CHARS = 65536


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
        dedup_ttl_seconds: int = DEDUP_TTL_SECONDS,
        max_seen_ids: int = 20000,
    ) -> None:
        self._messages = messages or message_repository
        self._presence = presence or presence_repository
        # Resolved at call time (module attribute) so tests can swap the
        # process registry after construction.
        self._lookup = registry_lookup or _default_registry_lookup
        # In-process replay window: envelope id -> monotonic seen-at.
        self._seen_ids: dict[tuple[str, str], float] = {}
        self._dedup_ttl = dedup_ttl_seconds
        self._max_seen_ids = max_seen_ids

    def _is_duplicate(self, sender_id: str, message_id: str) -> bool:
        """Track envelope ids seen in the last TTL; True => drop (replay).

        The window is in-process only (documented: cross-restart replay
        protection is the client's job via unique ids/nonces) and is bounded
        with a worst-case FIFO eviction.
        """
        now = time.monotonic()
        stale = [
            key
            for key, seen_at in self._seen_ids.items()
            if now - seen_at > self._dedup_ttl
        ]
        for key in stale:
            del self._seen_ids[key]

        key = (sender_id, message_id)
        if key in self._seen_ids:
            return True
        if len(self._seen_ids) >= self._max_seen_ids:
            oldest = min(self._seen_ids, key=self._seen_ids.get)
            del self._seen_ids[oldest]
        self._seen_ids[key] = now
        return False

    async def handle_message(self, sender_id: str, raw: str) -> None:
        """Process one inbound frame: forward, queue, or drop. Never raises."""
        # Bound the frame before parsing so oversized input never reaches the
        # journal/presence/delivery code. Logged without any payload content.
        if len(raw) > MAX_WS_MESSAGE_CHARS:
            logger.warning("dropping oversized websocket message from %s", sender_id)
            return

        envelope = normalize_envelope(raw, sender_id)
        if envelope is None:
            logger.warning("dropping invalid message envelope from %s", sender_id)
            return

        recipient_id = envelope["recipient"]
        if self._is_duplicate(sender_id, envelope["id"]):
            logger.info(
                "dropping duplicate envelope %s from %s", envelope["id"], sender_id
            )
            return

        # Build the payload to forward (server never decrypts)
        forward = json.dumps(envelope)

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

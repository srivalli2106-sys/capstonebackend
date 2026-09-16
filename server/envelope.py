"""envelope.py — the message envelope wire format (Phase 11).

The WebSocket relay stops passing loose ``{"to": ..., "data": ...}`` frames
and instead exchanges a structured **message envelope**. Payloads stay opaque
encrypted blobs — the server validates the envelope's routing and identity
contract, and never inspects ``data``.

Inbound frame (client -> server):

    {
      "id": "<26-char message id>",
      "type": "text | file | session_init | session_accept |
              delivery_receipt | read_receipt | typing",
      "recipient": "<user_id>",
      "data": "<opaque application payload>"
    }

Servers are authoritative over identity and time. ``sender``, ``timestamp``
and ``version`` are never trusted from the client — they are set here, so a
client cannot spoof another sender and the timestamp reflects server receipt:

Delivered/queued envelope (server -> recipient; this is what is stored in the
offline queue and flushed verbatim on reconnect):

    {
      "version": 1,
      "id": ...,
      "type": ...,
      "sender": "<authenticated sender>",
      "recipient": ...,
      "timestamp": 1750000000000,     # epoch milliseconds, server clock
      "data": ...
    }

See docs/PROTOCOL.md for the full protocol description (ordering, replay
protection, offline queue semantics, and how the E2EE phases plug into the
type catalog).
"""

from __future__ import annotations

import json
import logging
import time
from enum import Enum

from .message_id import is_valid_message_id

logger = logging.getLogger(__name__)

ENVELOPE_VERSION = 1

# Upper bound on the opaque payload of one envelope (characters). The whole
# frame is bounded separately by MAX_WS_MESSAGE_CHARS at the transport edge.
MAX_DATA_CHARS = 65520
MAX_USER_ID_LENGTH = 64

# Seconds a delivered/queued id stays in the in-process dedup window.
DEDUP_TTL_SECONDS = 300


class MessageType(str, Enum):
    """The formal catalog of message types the server will relay.

    ``text`` and ``file`` carry user content. ``session_init`` /
    ``session_accept`` are the X3DH handshake frames (opaque ciphertext);
    the server relays them like any other type and never interprets them.
    ``delivery_receipt`` / ``read_receipt`` / ``typing`` are small control
    frames used for status signalling; they follow the exact same envelope
    (the semantics live in the payload, which remains opaque to the server).
    """

    TEXT = "text"
    FILE = "file"
    SESSION_INIT = "session_init"
    SESSION_ACCEPT = "session_accept"
    DELIVERY_RECEIPT = "delivery_receipt"
    READ_RECEIPT = "read_receipt"
    TYPING = "typing"


# Registered type names, in declaration order (also used by docs).
MESSAGE_TYPE_NAMES = tuple(member.value for member in MessageType)
_MESSAGE_TYPE_SET = frozenset(MESSAGE_TYPE_NAMES)


def is_supported_message_type(value: object) -> bool:
    """True when ``value`` names a registered message type."""
    return isinstance(value, str) and value in _MESSAGE_TYPE_SET


def _server_now_ms() -> int:
    return int(time.time() * 1000)


def normalize_envelope(
    raw: str, sender_id: str, *, now_ms: object = None
) -> dict | None:
    """Parse and validate one inbound frame into a server-authoritative
    envelope. Returns None (dropped) for any malformed or spoofed input.

    ``now_ms`` is injectable for deterministic tests; defaulting to the
    process clock.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if not isinstance(obj, dict):
        return None

    message_id = obj.get("id")
    message_type = obj.get("type")
    recipient = obj.get("recipient")
    data = obj.get("data")

    if not is_valid_message_id(message_id):
        logger.warning("invalid message id; dropping frame")
        return None
    if not is_supported_message_type(message_type):
        logger.warning("unsupported message type; dropping frame")
        return None
    if (
        not isinstance(recipient, str)
        or not recipient
        or len(recipient) > MAX_USER_ID_LENGTH
    ):
        logger.warning("invalid recipient; dropping frame")
        return None
    if not isinstance(data, str) or not data or len(data) > MAX_DATA_CHARS:
        logger.warning("invalid payload; dropping frame")
        return None

    timestamp = (now_ms or _server_now_ms)()
    if not isinstance(timestamp, int):
        raise TypeError("now_ms must return an int")

    # Server-authoritative envelope: sender, timestamp and version can never
    # be influenced by the client (a spoofed "sender" field is overwritten).
    return {
        "version": ENVELOPE_VERSION,
        "id": message_id,
        "type": message_type,
        "sender": sender_id,
        "recipient": recipient,
        "timestamp": timestamp,
        "data": data,
    }


def serialize_envelope(envelope: dict) -> str:
    """Serialize an envelope to the wire form (envelope dicts are JSON-safe)."""
    return json.dumps(envelope)

r"""message_id.py — ULID-style message identifiers (Phase 11).

Every envelope carries a globally unique, **time-ordered** message id so that
clients can reconcile delivery, order offline messages, and deduplicate
retries.

Format (26 characters, Crockford base32 — the standard ULID layout):

    tttttttttt rrrrrrrrrrrrrrrr
    \________/ \______________/
       48-bit       80-bit
     ms timestamp   randomness

Why ULID over UUID4:

  * UUID4 is random: two messages created a millisecond apart have no
    discoverable order. ULIDs sort lexicographically by creation time, which
    gives a deterministic order key for offline refetch and client-side
    reconciliation.
  * The id is still collision-resistant (80 random bits), so it doubles as a
    safe per-message nonce seed on both ends.

Guarantees provided here:

  * **Uniqueness**: each call draws fresh cryptographic randomness.
  * **Monotonic order**: if the wall clock goes backwards (or is coarse), the
    previous timestamp is reused so ids never produce a lower timestamp than
    the last one generated in this process.
"""

from __future__ import annotations

import os
import time

# Crockford base32 (no I/L/O/U — unambiguous even hand-transcribed).
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_BASE = len(_ALPHABET)

_ENCODED_LENGTH = 26
_TIMESTAMP_CHARS = 10  # 48 bits fit in 10 base32 chars (50 bits)
_RANDOM_CHARS = 16  # 80 random bits


def _encode(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_ALPHABET[value % _BASE])
        value //= _BASE
    return "".join(reversed(chars))


def _decode(encoded: str) -> int:
    value = 0
    for char in encoded:
        value = value * _BASE + _ALPHABET.index(char)
    return value


# Last timestamp issued in this process; guarantees non-decreasing order.
_last_timestamp_ms = 0


def new_message_id() -> str:
    """Return a new, unique, time-ordered message id."""
    global _last_timestamp_ms

    now_ms = int(time.time() * 1000)
    # A clock regression (or a coarse clock) must never *decrease* ids.
    if now_ms <= _last_timestamp_ms:
        now_ms = _last_timestamp_ms
    _last_timestamp_ms = now_ms

    randomness = int.from_bytes(os.urandom(10), "big")
    return _encode(now_ms, _TIMESTAMP_CHARS) + _encode(
        randomness, _RANDOM_CHARS
    )


def is_valid_message_id(value: object) -> bool:
    """True when ``value`` is a well-formed message id (26 Crockford chars)."""
    if not isinstance(value, str) or len(value) != _ENCODED_LENGTH:
        return False
    # The alphabet is ASCII uppercase; accept lowercase as equivalent.
    return all(char.upper() in _ALPHABET for char in value)


def message_timestamp_ms(value: str) -> int:
    """Return the creation timestamp (epoch millis) encoded in a message id."""
    return _decode(value[:_TIMESTAMP_CHARS])

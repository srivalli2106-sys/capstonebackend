"""
auth_store.py — Redis-backed authentication storage (Phase 6).

Two key families:

  auth_challenge:{user_id}  -> 32-byte nonce (hex). One outstanding
                               challenge per user; a new challenge replaces
                               the previous one. Short bounded TTL.
  auth_revoked:{jti}        -> "1" while the token's jti is blacklisted.
                               TTL is bounded by the token's remaining
                               lifetime (never permanent).

All operations fail loudly: a Redis driver error propagates so callers fail
closed (dependencies are security-critical here, unlike presence/queue
degradation). Challenge consumption is a single atomic command (GETDEL, or a
Lua fallback on servers < 6.2) — never a racy GET-then-DEL, so replay of the
same challenge cannot succeed twice, even concurrently.
"""

from __future__ import annotations

import secrets

from .redis_client import get_redis

_CHALLENGE_KEY_PREFIX = "auth_challenge:"
_REVOKED_KEY_PREFIX = "auth_revoked:"

# A challenge nonce is exactly 32 bytes, hex-encoded -> 64 hex characters.
NONCE_BYTES = 32
NONCE_HEX_CHARS = NONCE_BYTES * 2

# Atomic Lua fallback for Redis < 6.2 where GETDEL is unavailable. Returns 1
# only when the stored challenge matches the presented nonce (and deletes it).
_GETDEL_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if value == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
"""


# ---------------------------------------------------------------------------
# Challenges (proof of possession)
# ---------------------------------------------------------------------------


async def issue_challenge(user_id: str, ttl_seconds: int) -> str:
    """Store a fresh random challenge for ``user_id`` and return the nonce.

    The challenge is bound to ``user_id`` by its key and expires after
    ``ttl_seconds``. Invalidating any previously issued challenge implicitly.
    """
    nonce = secrets.token_hex(NONCE_BYTES)
    r = await get_redis()
    await r.set(f"{_CHALLENGE_KEY_PREFIX}{user_id}", nonce, ex=ttl_seconds)
    return nonce


async def consume_challenge(user_id: str, nonce: str) -> bool:
    """Atomically consume the challenge for ``user_id``.

    Returns True exactly once for the matching nonce — concurrent consumers
    can never both succeed (GETDEL/lua is atomic). A wrong, missing, or
    already-consumed (replayed) challenge returns False.
    """
    r = await get_redis()
    key = f"{_CHALLENGE_KEY_PREFIX}{user_id}"
    if hasattr(r, "getdel"):
        stored = await r.getdel(key)
        return stored == nonce
    result = await r.eval(_GETDEL_SCRIPT, 1, key, nonce)
    return bool(result)


# ---------------------------------------------------------------------------
# Token revocation (logout)
# ---------------------------------------------------------------------------


async def revoke_token(jti: str, ttl_seconds: int) -> None:
    """Blacklist ``jti`` for ``ttl_seconds`` (bounded by token lifetime)."""
    r = await get_redis()
    await r.set(f"{_REVOKED_KEY_PREFIX}{jti}", "1", ex=ttl_seconds)


async def is_token_revoked(jti: str) -> bool:
    """Return True when ``jti`` is currently blacklisted.

    A Redis error here propagates (fail closed): callers must not accept a
    token whose revocation status cannot be determined.
    """
    r = await get_redis()
    return await r.exists(f"{_REVOKED_KEY_PREFIX}{jti}") > 0

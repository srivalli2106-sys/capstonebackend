"""
middleware.py — HTTP auth utilities (compat surface) and rate limiting.

Phase 6 moved token creation/verification to :mod:`server.jwt_auth` and the
authenticated dependency (with revocation, fail-closed) to
:mod:`server.auth_service`. This module keeps the original public names so
existing consumers keep working:

  * ``create_token`` / ``decode_token`` — used by HTTP tests; the Phase 7
    WebSocket handshake authenticates through :mod:`server.ws_auth`.
  * ``require_auth`` — centralized dependency for protected HTTP routes.
  * ``check_rate_limit`` / ``check_rate_limit_for`` / ``RATE_LIMITS`` —
    Redis-backed sliding window shared by HTTP routes and the WebSocket
    connection/message rate gates (categories ``ws_connect``, ``ws_message``).
"""

from __future__ import annotations

import time

from fastapi import HTTPException, Request, status

from .auth_service import require_auth  # noqa: F401 - re-exported for routes
from .config import settings
from .jwt_auth import (  # noqa: F401 - re-exported for tests/consumers
    JWT_ALGORITHM,
    JWT_EXPIRY_HOURS,
    JWT_ISSUER,
    JWT_SECRET,
    create_access_token,
    verify_access_token,
)
from .redis_client import get_redis


def create_token(user_id: str) -> str:
    """Create a signed access token (see server.jwt_auth.create_access_token)."""
    return create_access_token(user_id)


def decode_token(token: str) -> dict:
    """Decode and fully validate a token: signature, algorithm, issuer,
    expiry, and required claims.

    NOTE: revocation is not checked here. HTTP-protected routes use
    ``require_auth`` (which checks revocation and fails closed on Redis
    errors); the WebSocket handshake uses :func:`server.ws_auth.verify_ws_token`.
    """
    return verify_access_token(token)


# ---------------------------------------------------------------------------
# Rate limiter (sliding window via Redis)
# ---------------------------------------------------------------------------

RATE_LIMITS: dict[str, tuple[int, int]] = {
    "register": (1, 3600),  # 1 request per hour per IP
    "login": (10, 60),  # 10 requests per minute
    "challenge": (10, 60),  # challenge requests per minute
    "verify": (20, 60),  # verification attempts per minute
    "logout": (30, 60),  # logout requests per minute
    "keys": (30, 60),  # 30 requests per minute
    "presence": (60, 60),  # 60 presence polls per minute
    "general": (100, 60),  # 100 requests per minute
    "ws_connect": (settings.ws_connect_rate_per_minute, 60),
    "ws_message": (settings.ws_message_rate_per_minute, 60),
}


async def check_rate_limit_for(identity: str, category: str = "general") -> None:
    """Sliding-window rate limit keyed by ``identity``.

    Raises HTTP 429 when the limit is exceeded. Redis failures propagate so
    callers decide their own failure policy (HTTP routes fail closed, the
    WebSocket gates degrade open).
    """
    limit, window = RATE_LIMITS.get(category, RATE_LIMITS["general"])
    key = f"ratelimit:{category}:{identity}"

    r = await get_redis()
    now = time.time()

    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, now - window)
    pipe.zadd(key, {str(now): now})
    pipe.zcard(key)
    pipe.expire(key, window)
    results = await pipe.execute()

    count = results[2]
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {category}. Try again later.",
        )


async def check_rate_limit(request: Request, category: str = "general") -> None:
    ip = request.client.host if request.client else "unknown"
    await check_rate_limit_for(ip, category)

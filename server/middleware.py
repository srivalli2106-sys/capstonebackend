"""
middleware.py — JWT authentication and rate limiting.

JWT:
  - Tokens carry {user_id, iat, exp}
  - Verified on protected endpoints and WebSocket upgrade

Rate limiter:
  - Per-IP sliding window using Redis
  - Configurable limits per endpoint category
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .redis_client import get_redis

# ---------------------------------------------------------------------------
# Config (from centralized Settings)
# ---------------------------------------------------------------------------

JWT_SECRET = settings.jwt_secret
JWT_ALGORITHM = settings.jwt_algorithm
JWT_EXPIRY_HOURS = settings.jwt_expiry_hours

_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# FastAPI dependency: require valid JWT
# ---------------------------------------------------------------------------


async def require_auth(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return decode_token(creds.credentials)


# ---------------------------------------------------------------------------
# Rate limiter (sliding window via Redis)
# ---------------------------------------------------------------------------

RATE_LIMITS: dict[str, tuple[int, int]] = {
    "register": (1, 3600),       # 1 request per hour per IP
    "login": (10, 60),           # 10 requests per minute
    "keys": (30, 60),            # 30 requests per minute
    "general": (100, 60),        # 100 requests per minute
}


async def check_rate_limit(request: Request, category: str = "general") -> None:
    limit, window = RATE_LIMITS.get(category, RATE_LIMITS["general"])
    ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:{category}:{ip}"

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

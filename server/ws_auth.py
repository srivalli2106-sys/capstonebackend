"""
ws_auth.py — WebSocket handshake authentication and connection guards.

Phase 7 replaces the query-string JWT handshake with a first-frame
authentication message::

    {"type": "auth", "token": "<JWT>"}

The handshake reuses the Phase 6 verification pipeline:
:func:`server.jwt_auth.verify_access_token` (signature/algorithm/issuer/
expiry/claims) followed by the Redis revocation check
(:func:`server.auth_store.is_token_revoked`). Revocation/verification
failures reject the connection with close code 4001; the token is never
logged or echoed.

Connection lifecycle helpers:

  * ``receive_auth_token`` — waits up to ``ws_auth_timeout_seconds`` for the
    first frame and guarantees the socket is closed on any handshake failure.
  * ``close_on_token_expiry`` — background task that closes the connection
    (4001) when the token expires; it also re-checks revocation periodically
    so a logout terminates the live connection promptly.
  * ``allow_ws_connect`` / ``allow_ws_message`` — Redis sliding-window rate
    gates. Over-limit returns False (the endpoint refuses 1013 / drops the
    message); any Redis error degrades open so an operational blip never
    kills live connectivity.

Logging is parameterized and contains no token material: conn/user identifiers
only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from asyncio import sleep as _sleep

from fastapi import HTTPException
from starlette.websockets import WebSocket

from .auth_store import is_token_revoked
from .config import settings
from .jwt_auth import verify_access_token
from .middleware import check_rate_limit_for
from .ws_registry import close_websocket

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Close codes and reasons (reasons are deliberately generic/short)
# ---------------------------------------------------------------------------

WS_NORMAL_CLOSE = 1000
WS_GOING_AWAY = 1001
WS_TOO_LARGE = 1009
WS_CAPACITY = 1013
WS_REPLACED = 4000
WS_AUTH_REQUIRED = 4001
WS_POLICY_VIOLATION = 4003
WS_IDLE_TIMEOUT = 4008

REASON_AUTH_FAILED = "Authentication failed"
REASON_AUTH_TIMEOUT = "Authentication timed out"
REASON_SESSION_EXPIRED = "Session expired"
REASON_REPLACED = "Replaced by new connection"
REASON_GOING_AWAY = "Server shutting down"
REASON_TOO_LARGE = "Message too large"
REASON_CAPACITY = "Server at capacity"
REASON_RATE_LIMITED = "Rate limit exceeded"
REASON_POLICY = "Policy violation"
REASON_IDLE_TIMEOUT = "Idle timeout"


class WsAuthError(Exception):
    """Rejection with an explicit close code and reason (never token bytes)."""

    def __init__(self, code: int, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"websocket close {code}: {reason}")


def new_connection_id() -> str:
    """Opaque, collision-resistant identifier for one connection."""
    return secrets.token_hex(8)


# ---------------------------------------------------------------------------
# First-frame authentication handshake
# ---------------------------------------------------------------------------


async def receive_ws_event(ws: WebSocket) -> tuple[str, object] | None:
    """Translate a raw ASGI websocket message into (kind, value).

    Returns ``("text", str)``, ``("bytes", bytes)``, ``("ping", None)``,
    ``("pong", None)``, ``("disconnect", code)`` or None for anything
    unexpected. Ping/pong are control keepalive events: the caller treats
    them as activity (they reset the idle window) and never as messages.
    The caller owns the connection and is the only receiver, so no unexpected
    messages should occur after accept.
    """
    message = await ws.receive()
    mtype = message.get("type")
    if mtype == "websocket.receive":
        if message.get("text") is not None:
            return ("text", message["text"])
        if "bytes" in message:
            return ("bytes", message["bytes"])
        return None
    if mtype == "websocket.ping":
        return ("ping", None)
    if mtype == "websocket.pong":
        return ("pong", None)
    if mtype == "websocket.disconnect":
        return ("disconnect", message.get("code", WS_NORMAL_CLOSE))
    return None


async def keepalive_ping(ws: WebSocket, interval: float) -> None:
    """Send a server-initiated ping every ``interval`` seconds until the
    socket dies. A WebSocket peer answers pings automatically (protocol
    level); healthy idle connections therefore keep producing pongs that
    reset the route's idle window, and NAT/proxy tunnels stay warm. Errors
    mean the socket is gone: the task exits silently. An interval <= 0 is a
    no-op (keepalive disabled).
    """
    if interval <= 0:
        return
    while True:
        await _sleep(interval)
        try:
            await ws.send({"type": "websocket.ping"})
        except Exception:
            return


async def receive_ws_event_with_idle_timeout(
    ws: WebSocket,
) -> tuple[str, object] | None:
    """Like :func:`receive_ws_event`, but bounded by the idle timeout.

    A connection that sends no application frame within
    ``ws_idle_timeout_seconds`` is condemned: the route closes it (4008).
    ``wait_for`` cancels the pending receive, so a timed-out receive cannot
    later deliver a stale frame to a different owner.
    """
    timeout = settings.ws_idle_timeout_seconds
    if timeout > 0:
        try:
            return await asyncio.wait_for(
                receive_ws_event(ws), timeout=timeout
            )
        except asyncio.TimeoutError:
            raise WsAuthError(WS_IDLE_TIMEOUT, REASON_IDLE_TIMEOUT) from None
    return await receive_ws_event(ws)


def parse_auth_frame(raw: str) -> str:
    """Extract the JWT from an auth frame, or raise WsAuthError (4001)."""
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED) from None
    if not isinstance(body, dict):
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED)
    if body.get("type") != "auth":
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED)
    token = body.get("token")
    if not isinstance(token, str) or not token:
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED)
    return token


async def receive_auth_token(ws: WebSocket) -> str | None:
    """Wait for the first frame and require a valid auth message.

    Returns the JWT on success, None when the peer disconnected during the
    handshake, and raises ``WsAuthError`` on timeout, binary-first-frame, or
    a malformed/absent auth message (the caller closes the socket).
    """
    try:
        event = await asyncio.wait_for(
            receive_ws_event(ws), timeout=settings.ws_auth_timeout_seconds
        )
    except asyncio.TimeoutError:
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_TIMEOUT) from None
    if event is None:
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED)
    kind, value = event
    if kind == "disconnect":
        return None
    if kind == "bytes":
        raise WsAuthError(WS_POLICY_VIOLATION, REASON_POLICY)
    return parse_auth_frame(value)


async def verify_ws_token(token: str) -> dict:
    """Verify a JWT and its revocation status, or raise WsAuthError (4001).

    Any verification or storage failure fails closed: an undecidable state is
    treated as a rejection.
    """
    try:
        claims = verify_access_token(token)
    except Exception:
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED) from None
    try:
        revoked = await is_token_revoked(claims["jti"])
    except Exception:
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_AUTH_FAILED) from None
    if revoked:
        raise WsAuthError(WS_AUTH_REQUIRED, REASON_SESSION_EXPIRED)
    return claims


# ---------------------------------------------------------------------------
# Token lifetime watcher
# ---------------------------------------------------------------------------


def close_on_token_expiry(ws: WebSocket, claims: dict) -> asyncio.Task:
    """Spawn the background lifetime watcher for this connection."""
    return asyncio.create_task(_watch_token_lifetime(ws, claims))


async def _watch_token_lifetime(ws: WebSocket, claims: dict) -> None:
    """Close 4001 when the JWT expires or is revoked (checked periodically).

    The revocation re-check makes a logout terminate the live connection
    promptly instead of waiting for natural expiry. A failed revocation read
    fails closed: the connection is closed rather than carried on an
    unverifiable token.
    """
    interval = max(1, settings.ws_presence_ttl_seconds // 10)
    exp = int(claims["exp"])
    while True:
        remaining = exp - int(time.time())
        if remaining <= 0:
            await close_websocket(ws, WS_AUTH_REQUIRED, REASON_SESSION_EXPIRED)
            return
        try:
            revoked = await is_token_revoked(claims["jti"])
        except Exception:
            await close_websocket(
                ws, WS_AUTH_REQUIRED, REASON_SESSION_EXPIRED
            )
            return
        if revoked:
            await close_websocket(ws, WS_AUTH_REQUIRED, REASON_SESSION_EXPIRED)
            return
        await _sleep(min(interval, remaining))


# ---------------------------------------------------------------------------
# Rate gates (degrade open on Redis failures)
# ---------------------------------------------------------------------------


async def allow_ws_connect(identity: str) -> bool:
    """Return False when the connect rate limit is exceeded.

    Redis failures degrade open (log + allow): the connect gate is
    operational, not a security boundary.
    """
    try:
        await check_rate_limit_for(identity, "ws_connect")
    except HTTPException:
        return False
    except Exception:
        logger.warning("rate limiter unavailable for ws connect; allowing")
    return True


async def allow_ws_message(user_id: str) -> bool:
    """Return False when the per-user message rate limit is exceeded.

    False drops the offending frame only; the connection stays alive. Redis
    failures degrade open (log + allow) for the same reason as above.
    """
    try:
        await check_rate_limit_for(user_id, "ws_message")
    except HTTPException:
        return False
    except Exception:
        logger.warning("rate limiter unavailable for ws message; allowing")
    return True

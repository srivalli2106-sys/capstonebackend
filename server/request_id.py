"""
request_id.py — HTTP request-ID correlation (Phase 2).

Request-ID policy, applied consistently everywhere:

* **Generated IDs** are UUIDv4 hex strings: exactly 32 lowercase hexadecimal
  characters, produced by ``uuid.uuid4()`` (backed by ``os.urandom``, i.e.
  cryptographically random).
* **Incoming ``X-Request-ID`` headers** are honored only when the value is at
  most :data:`_MAX_HEADER_LENGTH` characters long and contains only
  characters from the safe set ``[A-Za-z0-9._-]``. Anything longer or
  containing other characters is discarded and replaced with a freshly
  generated ID.

The active request ID is exposed through the :data:`request_id_contextvar`
ContextVar so handlers can read it, and is imported into every log record by
``RequestContextFilter`` in :mod:`server.logging_config`.

WebSocket connections are passed through untouched — message payloads are
never inspected or logged.
"""

from __future__ import annotations

import logging
import string
import time
import uuid
from contextvars import ContextVar
from typing import Any

logger = logging.getLogger(__name__)

_MAX_HEADER_LENGTH = 64
_SAFE_CHARS = frozenset(string.ascii_letters + string.digits + "._-")

request_id_contextvar: ContextVar[str | None] = ContextVar(
    "request_id", default=None
)


def get_current_request_id() -> str | None:
    """Return the request ID that correlates the current context (if any)."""
    return request_id_contextvar.get()


def new_request_id() -> str:
    """Generate a fresh request ID: 32 lowercase hex characters (UUIDv4)."""
    return uuid.uuid4().hex


def normalize_request_id(header_value: str | None) -> str:
    """Return a usable request ID for ``header_value`` per the policy above.

    A missing, oversized, or unsafe value is replaced with a generated ID.
    """
    if not header_value:
        return new_request_id()
    if len(header_value) > _MAX_HEADER_LENGTH:
        return new_request_id()
    if not _SAFE_CHARS.issuperset(header_value):
        return new_request_id()
    return header_value


def _with_request_id_header(
    headers: list[tuple[bytes, bytes]], request_id: str
) -> list[tuple[bytes, bytes]]:
    """Return ``headers`` with ``X-Request-ID`` set to ``request_id``."""
    encoded = request_id.encode("ascii")
    others = [
        (name, value)
        for name, value in headers
        if name.lower() != b"x-request-id"
    ]
    return others + [(b"x-request-id", encoded)]


class RequestIDMiddleware:
    """ASGI middleware correlating every HTTP request with one request ID.

    * Reads and normalizes the incoming ``X-Request-ID``.
    * Exposes the active ID through :data:`request_id_contextvar`.
    * Echoes the ID back in the ``X-Request-ID`` response header.
    * Emits one completion record per HTTP request: method, path, status,
      duration (ms) and request ID. No request body, query string, or header
      values other than the request ID are ever logged.
    * Resets the ContextVar after the request, in all paths.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(
        self, scope: dict[str, Any], receive: Any, send: Any
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming: str | None = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"x-request-id":
                incoming = value.decode("latin-1")
                break

        request_id = normalize_request_id(incoming)
        token = request_id_contextvar.set(request_id)
        started = time.perf_counter()

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = _with_request_id_header(
                    message.get("headers", []), request_id
                )
                duration_ms = round((time.perf_counter() - started) * 1000, 2)
                logger.info(
                    "http request completed",
                    extra={
                        "method": scope.get("method", "-"),
                        "path": scope.get("path", "-"),
                        "status": message.get("status", "-"),
                        "duration_ms": duration_ms,
                        "request_id": request_id,
                    },
                )
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            request_id_contextvar.reset(token)

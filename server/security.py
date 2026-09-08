"""
security.py — Phase 5 HTTP security middleware (ASGI).

SecurityHeadersMiddleware
    Adds baseline HTTP security headers to every HTTP response:

    * ``X-Content-Type-Options: nosniff``
    * ``X-Frame-Options: DENY``
    * ``Referrer-Policy: no-referrer``
    * ``Strict-Transport-Security`` — only when the deployment is actually
      served over TLS (``settings.secure_transport``). HSTS is never emitted
      for plaintext local development.

    Headers are injected at ``http.response.start``, so they are present on
    successful responses, error responses, and CORS/preflight responses
    alike, and they never conflict with ``X-Request-ID`` (set by
    :class:`server.request_id.RequestIDMiddleware`) or the CORS headers.

AllowedHostsMiddleware
    Host-header validation mirroring Starlette's TrustedHostMiddleware, but
    rendering the Phase-3 error contract
    ``{"error": {"code", "message", "request_id"}}`` for rejections. It is
    registered after RequestIDMiddleware so every rejection still carries a
    request ID. ``"*"`` (the development/test default) disables validation.

    Proxy note: the list is the deployment's public/termination hostnames.
    No proxy parsing or scheme enforcement happens here — transport policy is
    configured separately via ``settings.secure_transport``.
"""

from __future__ import annotations

import logging
from typing import Any

from .exceptions import _error_response

logger = logging.getLogger(__name__)

_BASE_SECURITY_HEADERS: dict[bytes, bytes] = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
}

_HSTS_VALUE: bytes = b"max-age=31536000; includeSubDomains"


def _with_security_headers(
    headers: list[tuple[bytes, bytes]], hsts: bool
) -> list[tuple[bytes, bytes]]:
    """Add security headers, overriding any previously set same-name values."""
    result: list[tuple[bytes, bytes]] = [
        (name, value)
        for name, value in headers
        if name.lower() not in _BASE_SECURITY_HEADERS and name.lower() != b"strict-transport-security"
    ]
    result.extend(list(_BASE_SECURITY_HEADERS.items()))
    if hsts:
        result.append((b"strict-transport-security", _HSTS_VALUE))
    return result


class SecurityHeadersMiddleware:
    """ASGI middleware that stamps security headers onto HTTP responses."""

    def __init__(self, app: Any, *, hsts_enabled: bool = False) -> None:
        self.app = app
        self.hsts_enabled = hsts_enabled

    async def __call__(
        self, scope: dict[str, Any], receive: Any, send: Any
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = _with_security_headers(
                    message.get("headers", []), self.hsts_enabled
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)


class AllowedHostsMiddleware:
    """Reject requests whose Host header is not in the configured allowlist.

    WebSocket handshakes are validated the same way (the Host header is part
    of the handshake); no other scope type is touched.
    """

    def __init__(self, app: Any, *, allowed_hosts: list[str]) -> None:
        self.app = app
        self.allowed_hosts = set(allowed_hosts or [])

    def _host_is_allowed(self, host: str | None) -> bool:
        if not host:
            return False
        # IPv6 literal like "[::1]:8000" keeps the port outside the brackets.
        if host.startswith("["):
            end = host.find("]")
            hostname = host[1:end] if end != -1 else host
        else:
            hostname = host.split(":", 1)[0]
        return hostname in self.allowed_hosts

    async def __call__(
        self, scope: dict[str, Any], receive: Any, send: Any
    ) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if "*" in self.allowed_hosts:
            await self.app(scope, receive, send)
            return

        host_header: str | None = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"host":
                host_header = value.decode("latin-1")
                break

        if self._host_is_allowed(host_header):
            await self.app(scope, receive, send)
            return

        logger.warning(
            "rejected request for unallowed host %r", host_header
        )
        response = _error_response(400, "invalid_host", "Invalid Host header")
        await response(scope, receive, send)

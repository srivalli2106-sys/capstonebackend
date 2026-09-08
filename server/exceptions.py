"""
exceptions.py — centralized application error handling (Phase 3).

Defines a small application exception hierarchy plus the FastAPI exception
handlers that render every error through one consistent JSON contract:

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

* HTTP status codes and the existing client-facing message strings are
  preserved exactly.
* The active Phase 2 request ID is included in the error body whenever
  available; the ``X-Request-ID`` response header is added by
  ``RequestIDMiddleware`` in :mod:`server.request_id`.
* Unexpected exceptions are logged with a traceback internally and surfaced
  to the client as a generic HTTP 500 — tracebacks, class names, connection
  strings, env vars, secrets, and internal details are never returned.

Only the subclasses genuinely needed by the existing routes exist here.
JWT and rate-limit errors are intentionally still raised as
``fastapi.HTTPException`` (their unit tests pin that type) and are normalized
by the ``HTTPException`` handler below.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .request_id import get_current_request_id

logger = logging.getLogger(__name__)


class ApplicationError(Exception):
    """Base class for expected, client-facing application errors.

    Attributes:
        status_code: HTTP status to return.
        code: stable machine-readable error identifier.
        message: safe client-facing message.
    """

    status_code: int = 500
    code: str = "application_error"
    message: str = "Application error"

    def __init__(self, message: str | None = None) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message)


class InvalidRequest(ApplicationError):
    """Request was malformed or contained invalid values (HTTP 400)."""

    status_code = 400
    code = "invalid_request"
    message = "Invalid request"


class ResourceNotFound(ApplicationError):
    """A requested resource does not exist (HTTP 404)."""

    status_code = 404
    code = "not_found"
    message = "Not found"


class Conflict(ApplicationError):
    """The request conflicts with the current server state (HTTP 409)."""

    status_code = 409
    code = "conflict"
    message = "Conflict"


# ---------------------------------------------------------------------------
# Error response helper
# ---------------------------------------------------------------------------


def _error_response(
    status_code: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": get_current_request_id() or "-",
            }
        },
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


async def application_error_handler(
    request: Request, exc: ApplicationError
) -> JSONResponse:
    logger.warning(
        "application error: code=%s status=%d %s %s",
        exc.code,
        exc.status_code,
        request.method,
        request.url.path,
    )
    return _error_response(exc.status_code, exc.code, exc.message)


async def http_exception_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    message = (
        exc.detail if isinstance(exc.detail, str) and exc.detail else "Request failed"
    )
    logger.warning(
        "http error: status=%d %s %s",
        exc.status_code,
        request.method,
        request.url.path,
    )
    return _error_response(
        exc.status_code,
        f"http_{exc.status_code}",
        message,
        headers=exc.headers,
    )


async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    fields = [
        ".".join(str(part) for part in item["loc"] if part != "body")
        for item in exc.errors()
    ]
    logger.warning(
        "request validation failed for %s %s; fields: %s",
        request.method,
        request.url.path,
        ",".join(fields) if fields else "-",
    )
    return _error_response(422, "validation_error", "Request validation failed")


async def unexpected_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    logger.error(
        "unhandled exception: %s %s",
        request.method,
        request.url.path,
        exc_info=True,
    )
    return _error_response(500, "internal_error", "Internal server error")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def install_exception_handlers(app: FastAPI) -> None:
    """Register the centralized handlers on ``app``.

    Generic ``Exception`` and status ``500`` both route to the catch-all so
    that even failures escaping the router render structured, safe 500s.
    """
    app.add_exception_handler(ApplicationError, application_error_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    # Starlette's HTTPException is a distinct class from FastAPI's; route-level
    # 404/405s are raised by the Starlette router, so both must be covered.
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unexpected_exception_handler)
    app.add_exception_handler(500, unexpected_exception_handler)

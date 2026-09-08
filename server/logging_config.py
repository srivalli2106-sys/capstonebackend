"""
logging_config.py — centralized logging configuration (Phase 2).

Standard-library only. Configures the root logger with a single
``StreamHandler`` whose format is:

    *timestamp* | *level* | *logger name*
    | request_id=*<id>* *<method>* *<path>* *<status>* *<duration_ms>*
    | *message*

The dynamic fields are injected by :class:`RequestContextFilter`, so every
record from every logger is safe to format — even records emitted outside a
request context (they render as ``-``). Log level comes from
``settings.log_level``.

``setup_logging()`` is idempotent: handlers created here are marked and never
duplicated, no matter how many times it is called (import-time call sites,
tests, etc.).
"""

from __future__ import annotations

import logging
from typing import Final

from .config import settings
from .request_id import request_id_contextvar

LOG_FORMAT: Final = (
    "%(asctime)s | %(levelname)-8s | %(name)s "
    "| request_id=%(request_id)s %(method)s %(path)s %(status)s %(duration_ms)s "
    "| %(message)s"
)

_OPTIONAL_FIELDS: Final = ("method", "path", "status", "duration_ms")

_STREAM_HANDLER_ATTR: Final = "_secure_messaging_stream_handler"


class RequestContextFilter(logging.Filter):
    """Attach request-correlation fields to every emitted record.

    ``request_id`` is taken from the active ContextVar when the record does
    not already carry one; the remaining HTTP fields default to ``-``.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_contextvar.get() or "-"
        for field in _OPTIONAL_FIELDS:
            if not hasattr(record, field):
                setattr(record, field, "-")
        return True


def setup_logging(log_level: str | None = None) -> None:
    """Configure the root logger exactly once; repeated calls are no-ops.

    Uses ``settings.log_level`` unless ``log_level`` overrides it.
    """
    root = logging.getLogger()
    if any(
        getattr(handler, _STREAM_HANDLER_ATTR, False) for handler in root.handlers
    ):
        return

    handler = logging.StreamHandler()
    handler.addFilter(RequestContextFilter())
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    setattr(handler, _STREAM_HANDLER_ATTR, True)
    root.addHandler(handler)
    root.setLevel((log_level or settings.log_level).upper())

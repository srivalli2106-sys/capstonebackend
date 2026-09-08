"""
Phase 2 tests — request-ID policy, middleware behavior, and log correlation.

Infrastructure-free: no MongoDB or Redis required. The reused ``client``
fixture runs the app without the lifespan.
"""

from __future__ import annotations

import logging
import re

import pytest
from fastapi.testclient import TestClient

from server.logging_config import (
    _STREAM_HANDLER_ATTR,
    RequestContextFilter,
    setup_logging,
)
from server.request_id import (
    get_current_request_id,
    normalize_request_id,
    request_id_contextvar,
)

UUID4_HEX = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------------------
# Request-ID policy (documented behavior, tested directly)
# ---------------------------------------------------------------------------


def test_policy_generates_request_id_for_missing_header():
    assert UUID4_HEX.fullmatch(normalize_request_id(None))
    assert UUID4_HEX.fullmatch(normalize_request_id(""))


@pytest.mark.parametrize("safe", ["abc-123_DEF.9", "0", "a" * 64])
def test_policy_preserves_safe_incoming_values(safe):
    assert normalize_request_id(safe) == safe


def test_policy_replaces_oversized_incoming_value():
    assert UUID4_HEX.fullmatch(normalize_request_id("x" * 65))


@pytest.mark.parametrize("unsafe", ["a b", "a/b", "a;b", "a,b", "\u00e9"])
def test_policy_replaces_unsafe_incoming_values(unsafe):
    assert UUID4_HEX.fullmatch(normalize_request_id(unsafe))


# ---------------------------------------------------------------------------
# Request-ID middleware behavior (through the ASGI stack)
# ---------------------------------------------------------------------------


def test_health_returns_success_with_generated_request_id(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    request_id = response.headers.get("x-request-id")
    assert request_id is not None
    assert UUID4_HEX.fullmatch(request_id)


def test_response_always_contains_request_id_header(client: TestClient):
    response = client.get("/health")
    assert "x-request-id" in response.headers


def test_valid_incoming_request_id_is_preserved(client: TestClient):
    incoming = "abc-123_DEF.9"
    response = client.get("/health", headers={"X-Request-ID": incoming})
    assert response.headers.get("x-request-id") == incoming


def test_oversized_incoming_request_id_is_replaced(client: TestClient):
    incoming = "x" * 65
    response = client.get("/health", headers={"X-Request-ID": incoming})
    returned = response.headers.get("x-request-id")
    assert returned != incoming
    assert UUID4_HEX.fullmatch(returned)


@pytest.mark.parametrize("unsafe", ["a b", "a/b", "a;b", "a!b"])
def test_unsafe_incoming_request_id_is_replaced(client: TestClient, unsafe):
    response = client.get("/health", headers={"X-Request-ID": unsafe})
    returned = response.headers.get("x-request-id")
    assert returned != unsafe
    assert UUID4_HEX.fullmatch(returned)


def test_contextvar_is_reset_after_request(client: TestClient):
    assert get_current_request_id() is None
    client.get("/health")
    assert get_current_request_id() is None


# ---------------------------------------------------------------------------
# Log correlation
# ---------------------------------------------------------------------------


def test_completion_log_record_carries_request_context(client: TestClient, caplog):
    incoming = "req-42"
    with caplog.at_level(logging.INFO, logger="server.request_id"):
        client.get("/health", headers={"X-Request-ID": incoming})

    completion = [
        record
        for record in caplog.records
        if record.name == "server.request_id"
    ]
    assert len(completion) == 1
    record = completion[0]
    assert record.getMessage() == "http request completed"
    assert record.request_id == incoming
    assert record.method == "GET"
    assert record.path == "/health"
    assert record.status == 200
    assert record.duration_ms >= 0


def test_filter_defaults_outside_request_context():
    record = logging.LogRecord(
        name="server.something",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="a message",
        args=(),
        exc_info=None,
    )
    RequestContextFilter().filter(record)
    assert record.request_id == "-"
    assert record.method == "-"
    assert record.path == "-"
    assert record.status == "-"
    assert record.duration_ms == "-"


def test_setup_logging_is_idempotent():
    marked = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, _STREAM_HANDLER_ATTR, False)
    ]
    setup_logging()
    setup_logging()
    after = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, _STREAM_HANDLER_ATTR, False)
    ]
    assert len(after) == len(marked)
    assert request_id_contextvar.get() is None

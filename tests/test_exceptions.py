"""
Phase 3 tests — centralized error handling contract.

Infrastructure-free (no MongoDB/Redis). Mix of:

* direct handler invocations for exceptions not reachable over HTTP without a
  database (application errors, catch-all 500);
* real HTTP paths that never touch infrastructure: 422 validation happens
  before the endpoint runs, the 401 dependency runs before the handler,
  and unmatched routes raise a router-level 404.

Contract under test: every error is ``{"error": {"code", "message",
"request_id"}}`` with the HTTP status preserved and the Phase 2 request ID
echoed in both the body and the ``X-Request-ID`` response header.
"""

from __future__ import annotations

import json
import logging
import re

import pytest
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from server.exceptions import (
    Conflict,
    InvalidRequest,
    ResourceNotFound,
    application_error_handler,
    http_exception_handler,
    unexpected_exception_handler,
    validation_error_handler,
)
from server.request_id import get_current_request_id, request_id_contextvar

UUID4_HEX = re.compile(r"^[0-9a-f]{32}$")


def _request(method: str = "GET", path: str = "/") -> Request:
    return Request({"type": "http", "method": method, "path": path, "headers": []})


def _error_body(response) -> dict:
    return dict(json.loads(response.body.decode())["error"])


@pytest.fixture
def with_request_id():
    """Simulate being inside a request with an active request ID."""
    token = request_id_contextvar.set("test-req-1")
    yield "test-req-1"
    request_id_contextvar.reset(token)


# ---------------------------------------------------------------------------
# 1. Application exceptions
# ---------------------------------------------------------------------------


async def test_application_error_structured_response(with_request_id):
    response = await application_error_handler(
        _request("POST", "/auth/register"), Conflict("already registered")
    )
    assert response.status_code == 409
    assert _error_body(response) == {
        "code": "conflict",
        "message": "already registered",
        "request_id": "test-req-1",
    }


async def test_invalid_request_error_status_and_message():
    response = await application_error_handler(
        _request("POST", "/keys/upload"), InvalidRequest("ik_public must be hex")
    )
    assert response.status_code == 400
    body = _error_body(response)
    assert body["code"] == "invalid_request"
    assert body["message"] == "ik_public must be hex"


async def test_resource_not_found_error_status():
    response = await application_error_handler(
        _request("GET", "/keys/bundle/x"), ResourceNotFound("Key bundle not found")
    )
    assert response.status_code == 404
    assert _error_body(response)["code"] == "not_found"


# ---------------------------------------------------------------------------
# 2. HTTPException
# ---------------------------------------------------------------------------


async def test_http_exception_normalized_but_status_and_detail_preserved():
    response = await http_exception_handler(
        _request("GET", "/keys/bundle/x"), HTTPException(status_code=404, detail="User not found")
    )
    assert response.status_code == 404
    body = _error_body(response)
    assert body["code"] == "http_404"
    assert body["message"] == "User not found"


def test_http_exception_over_http_401_without_auth(client: TestClient):
    response = client.get("/keys/bundle/target")
    assert response.status_code == 401
    body = response.json()["error"]
    assert body["code"] == "http_401"
    assert body["message"] == "Missing bearer token"


def test_router_404_over_http(client: TestClient):
    response = client.get("/no-such-endpoint")
    assert response.status_code == 404
    body = response.json()["error"]
    assert body["code"] == "http_404"
    assert body["request_id"] == response.headers.get("x-request-id")


# ---------------------------------------------------------------------------
# 3. Validation errors -> structured 4xx
# ---------------------------------------------------------------------------


async def test_validation_error_handler_structured(with_request_id):
    exc = RequestValidationError(errors=[{"loc": ("body", "ik_public"), "msg": "field required", "type": "value_error.missing"}])
    response = await validation_error_handler(_request("POST", "/auth/register"), exc)
    assert response.status_code == 422
    assert _error_body(response)["code"] == "validation_error"
    assert _error_body(response)["request_id"] == "test-req-1"


def test_validation_error_over_http_422(client: TestClient):
    response = client.post("/auth/register", json={"user_id": "someuser"})
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "validation_error"


# ---------------------------------------------------------------------------
# 4/5. Unexpected exceptions -> safe generic 500
# ---------------------------------------------------------------------------


async def test_unexpected_exception_returns_generic_500(with_request_id):
    response = await unexpected_exception_handler(
        _request("GET", "/boom"), RuntimeError("secret-db-password")
    )
    assert response.status_code == 500
    body = _error_body(response)
    assert body["code"] == "internal_error"
    assert body["message"] == "Internal server error"
    assert body["request_id"] == "test-req-1"


async def test_unexpected_exception_does_not_leak_internal_details(caplog):
    response = await unexpected_exception_handler(
        _request("GET", "/boom"), RuntimeError("mongodb://user:secret@internal-host")
    )
    text = response.body.decode()
    assert "mongodb://" not in text
    assert "secret" not in text
    assert "RuntimeError" not in text
    assert "Traceback" not in text
    assert "internal-host" not in text


async def test_unexpected_exception_logged_with_traceback_and_request_id(caplog, with_request_id):
    with caplog.at_level(logging.ERROR, logger="server.exceptions"):
        await unexpected_exception_handler(_request("GET", "/boom"), ValueError("boom"))
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("GET" in r.getMessage() and "/boom" in r.getMessage() for r in error_records)
    matching = [r for r in error_records if getattr(r, "request_id", None) == "test-req-1"]
    assert matching, "no error record carried the request ID"
    assert matching[0].exc_info is not None


# ---------------------------------------------------------------------------
# 6-10. Request ID correlation on errors
# ---------------------------------------------------------------------------


def test_error_response_contains_request_id_in_body_and_header(client: TestClient):
    response = client.get("/no-such-endpoint")
    assert response.status_code == 404
    body_id = response.json()["error"]["request_id"]
    header_id = response.headers.get("x-request-id")
    assert body_id and header_id
    assert body_id == header_id
    assert UUID4_HEX.fullmatch(body_id)


def test_incoming_valid_request_id_preserved_on_error(client: TestClient):
    response = client.get(
        "/no-such-endpoint", headers={"X-Request-ID": "abc-123"}
    )
    body_id = response.json()["error"]["request_id"]
    assert body_id == "abc-123"
    assert response.headers.get("x-request-id") == "abc-123"


@pytest.mark.parametrize("bad", ["x" * 65, "a b/c"])
def test_invalid_or_oversized_request_id_replaced_on_error(client: TestClient, bad):
    response = client.get("/no-such-endpoint", headers={"X-Request-ID": bad})
    body_id = response.json()["error"]["request_id"]
    header_id = response.headers.get("x-request-id")
    assert body_id != bad
    assert body_id == header_id
    assert UUID4_HEX.fullmatch(body_id)


def test_contextvar_reset_after_failing_request(client: TestClient):
    assert get_current_request_id() is None
    response = client.get("/no-such-endpoint")
    assert response.status_code == 404
    assert get_current_request_id() is None


# ---------------------------------------------------------------------------
# 11. Successful /health unchanged
# ---------------------------------------------------------------------------


def test_health_unchanged(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

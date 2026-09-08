"""Route registration / OpenAPI tests (no external infrastructure)."""

from __future__ import annotations

from server.app import app

# Expected HTTP endpoints: path -> set of HTTP methods.
EXPECTED_HTTP = {
    "/health": {"GET"},
    "/auth/register": {"POST"},
    "/auth/login": {"POST"},
    "/keys/upload": {"POST"},
    "/keys/bundle/{target_user_id}": {"GET"},
    "/keys/prekeys/{target_user_id}": {"GET"},
}


# FastAPI registers these meta routes automatically; they are not ours.
_META_ROUTES = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def test_all_expected_http_routes_registered():
    registered = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path and methods:
            registered.setdefault(path, set()).update(methods)

    for path, methods in EXPECTED_HTTP.items():
        assert registered.get(path) == methods, path
    assert set(registered) - set(EXPECTED_HTTP) <= _META_ROUTES


def test_websocket_relay_registered():
    ws_paths = [r.path for r in app.routes if getattr(r, "path", "") == "/ws"]
    assert len(ws_paths) == 1


def test_openapi_contains_http_routes_only():
    api_paths = set(app.openapi()["paths"].keys())
    assert api_paths == set(EXPECTED_HTTP.keys())

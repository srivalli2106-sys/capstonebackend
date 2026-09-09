"""
Integration test environment.

These tests exercise the real auth/key/WebSocket flows against live
MongoDB + Redis. They are only collected for execution when
RUN_INTEGRATION=1 is set (CI does this; the root conftest also skips them
otherwise). Rate limiting is neutralized here because register runs at
1 request/hour/IP, which would otherwise mask the flow tests.

On startup the MongoDB unique indexes are created (init_db) so that
duplicate registration is correctly rejected with 409.
"""

from __future__ import annotations

import asyncio
import os

import pytest
import pytest_asyncio

from server.db import init_db


async def _no_rate_limit(request, category: str = "general"):
    return None


@pytest_asyncio.fixture(autouse=True)
async def _integration_env(monkeypatch: pytest.MonkeyPatch):
    if os.getenv("RUN_INTEGRATION") != "1":
        pytest.skip("requires RUN_INTEGRATION=1 and MongoDB + Redis")

    # Wait for MongoDB (CI service containers may not be ready instantly).
    last_error: Exception | None = None
    for _ in range(30):
        try:
            await init_db()
            break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            await asyncio.sleep(1)
    else:
        raise RuntimeError("MongoDB not reachable") from last_error

    monkeypatch.setattr("server.routes.auth.check_rate_limit", _no_rate_limit)
    monkeypatch.setattr("server.routes.keys.check_rate_limit", _no_rate_limit)

    async def _ws_allow(identity: str) -> bool:
        return True

    # WebSocket connect/message rate gates are unit-tested; the flow tests
    # should not be subject to the sliding-window limits.
    monkeypatch.setattr("server.ws_auth.allow_ws_connect", _ws_allow)
    monkeypatch.setattr("server.ws_auth.allow_ws_message", _ws_allow)

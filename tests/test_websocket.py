"""WebSocket auth-rejection tests (no external infrastructure).

Connecting with an invalid JWT must fail fast with close code 4001,
before any Redis/MongoDB interaction.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def test_ws_rejects_invalid_token(client: TestClient):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws?token=not-a-valid-token") as ws:
            ws.send_text("{}")
    assert excinfo.value.code == 4001

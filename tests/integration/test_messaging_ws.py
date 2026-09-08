"""
WebSocket relay integration tests.

Require MongoDB (user presence records are keyed to registered users) and
Redis (online/offline status + offline queue). The relay itself only ever
forwards opaque blobs — the server never inspects message contents.
"""

from __future__ import annotations

import json

import pytest

from server.middleware import create_token

pytestmark = pytest.mark.integration

IK = "ab" * 32


def test_ws_relays_message_between_online_users(client):
    for uid in ("ws_alice", "ws_bob"):
        assert client.post(
            "/auth/register", json={"user_id": uid, "ik_public": IK}
        ).status_code == 201

    token_a = create_token("ws_alice")
    token_b = create_token("ws_bob")

    with client.websocket_connect(f"/ws?token={token_a}") as ws_a:
        with client.websocket_connect(f"/ws?token={token_b}") as ws_b:
            ws_b.send_json({"to": "ws_alice", "data": "blob-1"})
            forwarded = json.loads(ws_a.receive_text())
            assert forwarded == {"from": "ws_bob", "data": "blob-1"}


def test_ws_queues_message_for_offline_user(client):
    for uid in ("ws_carol", "ws_dave", "ws_erin"):
        assert client.post(
            "/auth/register", json={"user_id": uid, "ik_public": IK}
        ).status_code == 201

    token_carol = create_token("ws_carol")
    token_dave = create_token("ws_dave")

    # Carol sends to Dave while Dave is offline -> queued in Redis.
    with client.websocket_connect(f"/ws?token={token_carol}") as ws_carol:
        ws_carol.send_json({"to": "ws_dave", "data": "offline-msg"})

    # When Dave connects, the queued message is flushed to him.
    with client.websocket_connect(f"/ws?token={token_dave}") as ws_dave:
        delivered = json.loads(ws_dave.receive_text())
        assert delivered == {"from": "ws_carol", "data": "offline-msg"}

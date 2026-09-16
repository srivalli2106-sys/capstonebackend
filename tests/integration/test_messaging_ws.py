"""
WebSocket relay integration tests.

Require MongoDB (user presence records are keyed to registered users) and
Redis (online/offline status + offline queue). The relay only ever forwards
opaque envelopes — the server never inspects message contents.
"""

from __future__ import annotations

import json

import pytest

from server.message_id import new_message_id
from server.middleware import create_token

pytestmark = pytest.mark.integration

IK = "ab" * 32


def _auth(token: str) -> str:
    return json.dumps({"type": "auth", "token": token})


def _msg(to: str, data: str) -> str:
    return json.dumps(
        {
            "id": new_message_id(),
            "type": "text",
            "recipient": to,
            "data": data,
        }
    )


def _assert_envelope(received: dict, *, sender: str, recipient: str, data: str):
    env = dict(received)
    timestamp = env.pop("timestamp")
    assert isinstance(timestamp, int)
    assert env["version"] == 1
    assert env["type"] == "text"
    assert len(env["id"]) == 26
    assert env["sender"] == sender
    assert env["recipient"] == recipient
    assert env["data"] == data


def test_ws_relays_message_between_online_users(client):
    for uid in ("ws_alice", "ws_bob"):
        assert client.post(
            "/auth/register", json={"user_id": uid, "ik_public": IK}
        ).status_code == 201

    token_a = create_token("ws_alice")
    token_b = create_token("ws_bob")

    with client.websocket_connect("/ws") as ws_a:
        ws_a.send_text(_auth(token_a))
        with client.websocket_connect("/ws") as ws_b:
            ws_b.send_text(_auth(token_b))
            ws_b.send_text(_msg("ws_alice", "blob-1"))
            forwarded = json.loads(ws_a.receive_text())
            _assert_envelope(forwarded, sender="ws_bob", recipient="ws_alice", data="blob-1")


def test_ws_queues_message_for_offline_user(client):
    for uid in ("ws_carol", "ws_dave", "ws_erin"):
        assert client.post(
            "/auth/register", json={"user_id": uid, "ik_public": IK}
        ).status_code == 201

    token_carol = create_token("ws_carol")
    token_dave = create_token("ws_dave")

    # Carol sends to Dave while Dave is offline -> queued in Redis.
    with client.websocket_connect("/ws") as ws_carol:
        ws_carol.send_text(_auth(token_carol))
        ws_carol.send_text(_msg("ws_dave", "offline-msg"))

    # When Dave connects, the queued message is flushed to him.
    with client.websocket_connect("/ws") as ws_dave:
        ws_dave.send_text(_auth(token_dave))
        delivered = json.loads(ws_dave.receive_text())
        _assert_envelope(delivered, sender="ws_carol", recipient="ws_dave", data="offline-msg")

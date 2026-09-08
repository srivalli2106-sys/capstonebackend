"""WebSocket relay Redis-failure policy tests (no infra required).

Phase 4 policy:
* presence failures degrade gracefully — they must not turn a valid message
  into an error (recipient is treated as offline, message queues)
* a failed queue write is NEVER claimed as queued — it is logged as an
  explicit failure and the sender's connection stays alive
* malformed payloads never touch Redis
"""

from __future__ import annotations

import json
import logging

from server.routes import messages as m


def _raw(to: str, data: str) -> str:
    return json.dumps({"to": to, "data": data})


async def test_presence_failure_falls_back_to_queue(monkeypatch):
    queued: list[tuple[str, str]] = []

    async def _is_online(user_id):
        raise RuntimeError("redis down")

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    monkeypatch.setattr(m, "is_online", _is_online)
    monkeypatch.setattr(m, "enqueue_message", _enqueue)
    monkeypatch.setattr(m, "_connections", {})

    await m._handle_message("alice", _raw("carol", "blob"))

    assert queued == [("carol", json.dumps({"from": "alice", "data": "blob"}))]


async def test_queue_failure_is_reported_and_never_claimed(monkeypatch, caplog):
    async def _is_online(user_id):
        return False

    async def _enqueue(user_id, payload):
        raise RuntimeError("redis down")

    monkeypatch.setattr(m, "is_online", _is_online)
    monkeypatch.setattr(m, "enqueue_message", _enqueue)
    monkeypatch.setattr(m, "_connections", {})

    with caplog.at_level(logging.INFO, logger="server.routes.messages"):
        await m._handle_message("alice", _raw("carol", "blob"))  # must not raise

    error_lines = [
        r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR
    ]
    assert any("NOT queued" in line for line in error_lines)
    assert not any("Queued message" in line for line in error_lines)


async def test_online_recipient_gets_forwarded_without_queueing(monkeypatch):
    sent: dict = {}

    async def _is_online(user_id):
        return True

    async def _enqueue(user_id, payload):
        raise AssertionError("must not enqueue for an online recipient")

    class FakeWS:
        async def send_text(self, payload):
            sent["payload"] = payload

    monkeypatch.setattr(m, "is_online", _is_online)
    monkeypatch.setattr(m, "enqueue_message", _enqueue)
    monkeypatch.setattr(m, "_connections", {"carol": FakeWS()})

    await m._handle_message("alice", _raw("carol", "blob"))

    assert json.loads(sent["payload"]) == {"from": "alice", "data": "blob"}


async def test_forward_send_failure_falls_back_to_queue(monkeypatch):
    queued: list[tuple[str, str]] = []

    async def _is_online(user_id):
        return True

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    class FailingWS:
        async def send_text(self, payload):
            raise RuntimeError("ws closed")

    monkeypatch.setattr(m, "is_online", _is_online)
    monkeypatch.setattr(m, "enqueue_message", _enqueue)
    monkeypatch.setattr(m, "_connections", {"carol": FailingWS()})

    await m._handle_message("alice", _raw("carol", "blob"))

    assert len(queued) == 1
    assert queued[0][0] == "carol"


async def test_invalid_payload_never_touches_redis(monkeypatch):
    called: list[str] = []

    async def _is_online(user_id):
        called.append("is_online")
        return False

    monkeypatch.setattr(m, "is_online", _is_online)

    await m._handle_message("alice", "not-json")
    assert called == []

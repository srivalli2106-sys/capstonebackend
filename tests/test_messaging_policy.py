"""MessageService delivery/queue policy tests (no infra required).

Phase 4 policy, applied to the service layer directly:
* presence failures degrade gracefully — they must not turn a valid message
  into an error (recipient is treated as offline, message queues)
* a failed queue write is NEVER claimed as queued — it is logged as an
  explicit failure and the sender's connection stays alive
* malformed payloads never touch Redis

MessageService is constructed with fakes for its injected repositories and
registry lookup, so no monkeypatching of module globals is needed.
"""

from __future__ import annotations

import json
import logging

from server.services.message_service import MessageService


def _raw(to: str, data: str) -> str:
    return json.dumps({"to": to, "data": data})


class _Messages:
    """Stand-in for the MessageRepository fake surface."""

    def __init__(self, enqueue=None, dequeue=None):
        self.queued: list[tuple[str, str]] = []
        self._enqueue = enqueue
        self._dequeue = dequeue

    async def enqueue_message(self, user_id: str, payload: str) -> None:
        if self._enqueue is not None:
            await self._enqueue(user_id, payload)
            return
        self.queued.append((user_id, payload))

    async def dequeue_all_messages(self, user_id: str) -> list[str]:
        if self._dequeue is not None:
            return await self._dequeue(user_id)
        return []


class _Presence:
    """Stand-in for the PresenceRepository fake surface."""

    def __init__(self, online=None):
        self._online = online

    async def is_online(self, user_id: str) -> bool:
        if self._online is not None:
            return await self._online(user_id)
        return False


def _registry(conn):
    def _lookup(user_id):
        return conn

    return _lookup


class _ConnStub:
    def __init__(self, websocket):
        self.websocket = websocket


async def test_presence_failure_falls_back_to_queue():
    queued: list[tuple[str, str]] = []

    async def _is_online(user_id):
        raise RuntimeError("redis down")

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    svc = MessageService(
        messages=_Messages(enqueue=_enqueue),
        presence=_Presence(online=_is_online),
        registry_lookup=_registry(None),
    )

    await svc.handle_message("alice", _raw("carol", "blob"))

    assert queued == [("carol", json.dumps({"from": "alice", "data": "blob"}))]


async def test_queue_failure_is_reported_and_never_claimed(caplog):
    async def _enqueue_fails(user_id, payload):
        raise RuntimeError("redis down")

    async def _offline(user_id):
        return False

    svc = MessageService(
        messages=_Messages(enqueue=_enqueue_fails),
        presence=_Presence(online=_offline),
        registry_lookup=_registry(None),
    )

    with caplog.at_level(logging.INFO, logger="server.services.message_service"):
        await svc.handle_message("alice", _raw("carol", "blob"))  # must not raise

    error_lines = [
        r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR
    ]
    assert any("NOT queued" in line for line in error_lines)
    assert not any("Queued message" in line for line in error_lines)


async def test_online_recipient_gets_forwarded_without_queueing():
    sent: dict = {}

    class FakeWS:
        async def send_text(self, payload):
            sent["payload"] = payload

    async def _must_not_enqueue(user_id, payload):
        raise AssertionError("must not enqueue for an online recipient")

    async def _online(user_id):
        return True

    conn = _ConnStub(FakeWS())
    svc = MessageService(
        messages=_Messages(enqueue=_must_not_enqueue),
        presence=_Presence(online=_online),
        registry_lookup=_registry(conn),
    )

    await svc.handle_message("alice", _raw("carol", "blob"))

    assert json.loads(sent["payload"]) == {"from": "alice", "data": "blob"}


async def test_forward_send_failure_falls_back_to_queue():
    queued: list[tuple[str, str]] = []

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    async def _online(user_id):
        return True

    class FailingWS:
        async def send_text(self, payload):
            raise RuntimeError("ws closed")

    conn = _ConnStub(FailingWS())
    svc = MessageService(
        messages=_Messages(enqueue=_enqueue),
        presence=_Presence(online=_online),
        registry_lookup=_registry(conn),
    )

    await svc.handle_message("alice", _raw("carol", "blob"))

    assert len(queued) == 1
    assert queued[0][0] == "carol"


async def test_invalid_payload_never_touches_redis():
    presence_calls: list[str] = []

    async def _online(user_id):
        presence_calls.append("is_online")
        return False

    async def _must_not_enqueue(user_id, payload):
        raise AssertionError("must not enqueue malformed payloads")

    svc = MessageService(
        messages=_Messages(enqueue=_must_not_enqueue),
        presence=_Presence(online=_online),
        registry_lookup=_registry(None),
    )

    await svc.handle_message("alice", "not-json")
    assert presence_calls == []


# ---------------------------------------------------------------------------
# flush_pending (queue drain on connect)
# ---------------------------------------------------------------------------


class _Recorder:
    def __init__(self):
        self.sent: list[str] = []

    async def send_text(self, payload):
        self.sent.append(payload)


async def test_flush_pending_delivers_in_order():
    sender = _Recorder()

    async def _pending(user_id):
        return ["m1", "m2"]

    svc = MessageService(
        messages=_Messages(dequeue=_pending),
        presence=_Presence(),
        registry_lookup=_registry(None),
    )

    await svc.flush_pending("alice", sender)

    assert sender.sent == ["m1", "m2"]


async def test_flush_pending_empty_is_noop():
    sender = _Recorder()

    async def _empty(user_id):
        return []

    svc = MessageService(
        messages=_Messages(dequeue=_empty),
        presence=_Presence(),
        registry_lookup=_registry(None),
    )

    await svc.flush_pending("alice", sender)

    assert sender.sent == []


async def test_flush_send_failure_requeues_failed_and_stops():
    requeued: list[tuple[str, str]] = []

    async def _enqueue(user_id, payload):
        requeued.append((user_id, payload))

    async def _pending(user_id):
        return ["m1", "m2"]

    class _FailingSender:
        def __init__(self):
            self.attempts = 0

        async def send_text(self, payload):
            self.attempts += 1
            if self.attempts == 2:
                raise RuntimeError("ws closed")

    sender = _FailingSender()
    svc = MessageService(
        messages=_Messages(enqueue=_enqueue, dequeue=_pending),
        presence=_Presence(),
        registry_lookup=_registry(None),
    )

    await svc.flush_pending("alice", sender)

    assert sender.attempts == 2
    # The failed message is re-queued; the flush stops there (Phase 4 parity).
    assert requeued == [("alice", "m2")]


async def test_flush_dequeue_failure_logs_warning_and_skips(caplog):
    def _boom(user_id):
        raise RuntimeError("redis down")

    svc = MessageService(
        messages=_Messages(dequeue=_boom),
        presence=_Presence(),
        registry_lookup=_registry(None),
    )

    with caplog.at_level(logging.WARNING, logger="server.services.message_service"):
        await svc.flush_pending("alice", _Recorder())

    assert "could not flush queued messages for alice" in caplog.text

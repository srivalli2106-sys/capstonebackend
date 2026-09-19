"""MessageService delivery/queue policy tests (no infra required).

Phase 4 policy, applied to the service layer directly:
* presence failures degrade gracefully — they must not turn a valid message
  into an error (recipient is treated as offline, message queues)
* a failed queue write is NEVER claimed as queued — it is logged as an
  explicit failure and the sender's connection stays alive
* malformed payloads never touch Redis

Phase 11 policy additions:
* inbound frames are normalized into enveloped, server-authoritative
  envelopes (sender/version/timestamp never trusted from the client)
* an envelope id repeated inside the dedup window is treated as a replay
  and dropped
* clients cannot spoof a foreign sender id via the wire frame

MessageService is constructed with fakes for its injected repositories and
registry lookup, so no monkeypatching of module globals is needed.
"""

from __future__ import annotations

import json
import logging

from server.message_id import new_message_id
from server.services.message_service import MessageService


def _raw(to: str, data: str, *, mid: str | None = None) -> str:
    return json.dumps(
        {
            "id": mid or new_message_id(),
            "type": "text",
            "recipient": to,
            "data": data,
        }
    )


def _assert_envelope(parsed: dict, *, sender: str, recipient: str, data: str) -> None:
    assert parsed["version"] == 1
    assert parsed["type"] == "text"
    assert parsed["sender"] == sender
    assert parsed["recipient"] == recipient
    assert parsed["data"] == data
    assert isinstance(parsed["id"], str) and len(parsed["id"]) == 26
    assert isinstance(parsed["timestamp"], int)


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

    assert len(queued) == 1
    _assert_envelope(
        json.loads(queued[0][1]), sender="alice", recipient="carol", data="blob"
    )


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

    error_lines = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
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

    _assert_envelope(
        json.loads(sent["payload"]), sender="alice", recipient="carol", data="blob"
    )


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
    _assert_envelope(
        json.loads(queued[0][1]), sender="alice", recipient="carol", data="blob"
    )


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


# ---------------------------------------------------------------------------
# Phase 11: envelope identity / replay protection
# ---------------------------------------------------------------------------


async def test_duplicate_envelope_id_is_dropped():
    sent: list[str] = []

    class FakeWS:
        async def send_text(self, payload):
            sent.append(payload)

    async def _online(user_id):
        return True

    conn = _ConnStub(FakeWS())
    svc = MessageService(
        messages=_Messages(),
        presence=_Presence(online=_online),
        registry_lookup=_registry(conn),
    )

    mid = new_message_id()
    await svc.handle_message("alice", _raw("carol", "blob", mid=mid))
    await svc.handle_message("alice", _raw("carol", "blob-again", mid=mid))

    assert len(sent) == 1
    assert json.loads(sent[0])["data"] == "blob"


async def test_distinct_ids_are_all_processed():
    sent: list[str] = []

    class FakeWS:
        async def send_text(self, payload):
            sent.append(payload)

    async def _online(user_id):
        return True

    svc = MessageService(
        messages=_Messages(),
        presence=_Presence(online=_online),
        registry_lookup=_registry(_ConnStub(FakeWS())),
    )

    await svc.handle_message("alice", _raw("carol", "one"))
    await svc.handle_message("alice", _raw("carol", "two"))

    assert len(sent) == 2


async def test_replay_window_expiry_allows_same_id_again():
    sent: list[str] = []

    class FakeWS:
        async def send_text(self, payload):
            sent.append(payload)

    async def _online(user_id):
        return True

    mid = new_message_id()
    svc = MessageService(
        messages=_Messages(),
        presence=_Presence(online=_online),
        registry_lookup=_registry(_ConnStub(FakeWS())),
        dedup_ttl_seconds=1,
    )

    await svc.handle_message("alice", _raw("carol", "one", mid=mid))
    assert len(sent) == 1

    # Force the window to expire without real sleeping.
    svc._seen_ids[("alice", mid)] -= 2.0

    await svc.handle_message("alice", _raw("carol", "two", mid=mid))
    assert len(sent) == 2


async def test_spoofed_sender_is_overwritten():
    sent: list[str] = []

    class FakeWS:
        async def send_text(self, payload):
            sent.append(payload)

    async def _online(user_id):
        return True

    conn = _ConnStub(FakeWS())
    svc = MessageService(
        messages=_Messages(),
        presence=_Presence(online=_online),
        registry_lookup=_registry(conn),
    )

    mid = new_message_id()
    frame = json.dumps(
        {
            "id": mid,
            "type": "text",
            "sender": "mallory",
            "recipient": "carol",
            "data": "blob",
        }
    )
    await svc.handle_message("alice", frame)

    _assert_envelope(
        json.loads(sent[0]), sender="alice", recipient="carol", data="blob"
    )


async def test_unknown_message_type_is_dropped():
    sent: list[str] = []

    class FakeWS:
        async def send_text(self, payload):
            sent.append(payload)

    async def _online(user_id):
        return True

    svc = MessageService(
        messages=_Messages(),
        presence=_Presence(online=_online),
        registry_lookup=_registry(_ConnStub(FakeWS())),
    )

    frame = json.dumps(
        {
            "id": new_message_id(),
            "type": "not-a-real-type",
            "recipient": "carol",
            "data": "blob",
        }
    )
    await svc.handle_message("alice", frame)

    assert sent == []


# ---------------------------------------------------------------------------
# Messaging UX phase: control-frame relay policy
# ---------------------------------------------------------------------------


def _raw_ctl(to: str, frame_type: str, data: str) -> str:
    return json.dumps(
        {
            "id": new_message_id(),
            "type": frame_type,
            "recipient": to,
            "data": data,
        }
    )


async def test_control_frame_forwarded_to_online_recipient():
    sent: list[str] = []

    class FakeWS:
        async def send_text(self, payload):
            sent.append(payload)

    async def _must_not_enqueue(user_id, payload):
        raise AssertionError("must not enqueue for an online recipient")

    async def _online(user_id):
        return True

    svc = MessageService(
        messages=_Messages(enqueue=_must_not_enqueue),
        presence=_Presence(online=_online),
        registry_lookup=_registry(_ConnStub(FakeWS())),
    )

    await svc.handle_message("alice", _raw_ctl("carol", "typing", "1"))

    assert len(sent) == 1
    parsed = json.loads(sent[0])
    assert parsed["type"] == "typing"
    assert parsed["sender"] == "alice"
    assert parsed["recipient"] == "carol"
    assert parsed["data"] == "1"


async def test_control_frame_dropped_not_queued_when_offline():
    queued: list[tuple[str, str]] = []

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    async def _offline(user_id):
        return False

    svc = MessageService(
        messages=_Messages(enqueue=_enqueue),
        presence=_Presence(online=_offline),
        registry_lookup=_registry(None),
    )

    for frame_type, data in (
        ("typing", "1"),
        ("delivery_receipt", "msg-wire-id"),
        ("read_receipt", "msg-wire-id"),
    ):
        await svc.handle_message("alice", _raw_ctl("carol", frame_type, data))

    assert queued == []


async def test_control_frame_dropped_when_forward_fails():
    queued: list[tuple[str, str]] = []

    class FailingWS:
        async def send_text(self, payload):
            raise RuntimeError("ws closed")

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    async def _online(user_id):
        return True

    svc = MessageService(
        messages=_Messages(enqueue=_enqueue),
        presence=_Presence(online=_online),
        registry_lookup=_registry(_ConnStub(FailingWS())),
    )

    await svc.handle_message("alice", _raw_ctl("carol", "read_receipt", "x"))
    await svc.handle_message("alice", _raw_ctl("carol", "typing", "0"))

    assert queued == []


async def test_text_message_still_queued_for_offline_recipient():
    queued: list[tuple[str, str]] = []

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    async def _offline(user_id):
        return False

    svc = MessageService(
        messages=_Messages(enqueue=_enqueue),
        presence=_Presence(online=_offline),
        registry_lookup=_registry(None),
    )

    await svc.handle_message("alice", _raw("carol", "blob"))
    assert len(queued) == 1

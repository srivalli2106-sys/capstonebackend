"""PresenceService lifecycle/decision tests (no infra required).

Pin the Phase 4 degrade-instead-of-fail policy for the best-effort presence
markers: connection establishment and teardown must never fail due to Redis.
"""

from __future__ import annotations

import logging

from server.services.presence_service import PresenceService


class _Presence:
    """Records calls; individual methods can be turned into failures."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.fail: set[str] = set()

    async def set_online(self, user_id):
        self._record("set_online", user_id)

    async def set_offline(self, user_id):
        self._record("set_offline", user_id)

    async def register_connection(self, user_id, connection_id):
        self._record("register_connection", user_id, connection_id)

    async def remove_connection(self, user_id):
        self._record("remove_connection", user_id)

    def _record(self, *args):
        if args[0] in self.fail:
            raise RuntimeError("redis down")
        self.calls.append(args)


async def test_connect_marks_online_and_registers():
    fake = _Presence()
    svc = PresenceService(presence=fake)

    await svc.connect("alice", "c1")

    assert fake.calls == [
        ("set_online", "alice"),
        ("register_connection", "alice", "c1"),
    ]


async def test_connect_set_online_failure_still_registers_connection(caplog):
    fake = _Presence()
    fake.fail.add("set_online")
    svc = PresenceService(presence=fake)

    with caplog.at_level(logging.WARNING, logger="server.services.presence_service"):
        await svc.connect("alice", "c1")

    assert ("register_connection", "alice", "c1") in fake.calls
    assert "redis presence unavailable for alice at connect" in caplog.text


async def test_connect_register_failure_logs_and_does_not_raise(caplog):
    fake = _Presence()
    fake.fail.add("register_connection")
    svc = PresenceService(presence=fake)

    with caplog.at_level(logging.WARNING, logger="server.services.presence_service"):
        await svc.connect("alice", "c1")

    assert ("set_online", "alice") in fake.calls
    assert "redis connection registration unavailable for alice" in caplog.text


async def test_clear_removes_both_markers_in_order():
    fake = _Presence()
    svc = PresenceService(presence=fake)

    await svc.clear("alice")

    assert fake.calls == [("set_offline", "alice"), ("remove_connection", "alice")]


async def test_clear_degrades_gracefully_on_partial_failure(caplog):
    fake = _Presence()
    fake.fail.add("set_offline")
    svc = PresenceService(presence=fake)

    with caplog.at_level(logging.WARNING, logger="server.services.presence_service"):
        await svc.clear("alice")

    # remove_connection still attempted even though set_offline failed.
    assert ("remove_connection", "alice") in fake.calls
    assert "redis unavailable during set_offline cleanup for alice" in caplog.text


async def test_keep_alive_stops_immediately_when_conn_id_superseded():
    fake = _Presence()
    svc = PresenceService(presence=fake)

    def _current(user_id):
        return "c2"  # replacement already present

    await svc.keep_alive("alice", "c1", _current, interval=0)

    assert fake.calls == []


async def test_keep_alive_refreshes_while_current_then_stops():
    fake = _Presence()
    svc = PresenceService(presence=fake)
    seq = iter(["c1", "c1", "c2"])

    def _current(user_id):
        return next(seq)

    await svc.keep_alive("alice", "c1", _current, interval=0)

    assert fake.calls == [
        ("set_online", "alice"),
        ("register_connection", "alice", "c1"),
        ("set_online", "alice"),
        ("register_connection", "alice", "c1"),
    ]


async def test_keep_alive_refresh_failure_logs_and_continues_until_superseded(caplog):
    class _FailingPresence(_Presence):
        async def set_online(self, user_id):
            self.calls.append(("set_online", user_id))
            raise RuntimeError("redis down")

        async def register_connection(self, user_id, connection_id):
            self.calls.append(("register_connection", user_id, connection_id))
            raise RuntimeError("redis down")

    fake = _FailingPresence()
    svc = PresenceService(presence=fake)
    seq = iter(["c1", "c2"])

    def _current(user_id):
        return next(seq)

    with caplog.at_level(logging.WARNING, logger="server.services.presence_service"):
        await svc.keep_alive("alice", "c1", _current, interval=0)

    assert "presence refresh failed for alice" in caplog.text
    # It must not spin forever after a failure: once superseded, it returns
    # after a single attempted refresh (set_online raised before the register
    # call, so exactly one call was recorded).
    assert len(fake.calls) == 1

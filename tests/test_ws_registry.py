"""WsRegistry unit tests (no infrastructure required)."""

from __future__ import annotations

from server.ws_registry import WsConnection, WsRegistry


def _conn(conn_id: str, user_id: str, websocket=None) -> WsConnection:
    return WsConnection(
        conn_id=conn_id, user_id=user_id, websocket=websocket or object(), claims={}
    )


async def test_try_reserve_respects_budget_and_release_slot():
    reg = WsRegistry(max_connections=2)
    assert await reg.try_reserve() is True
    assert await reg.try_reserve() is True
    assert await reg.try_reserve() is False
    await reg.release_slot()
    await reg.release_slot()
    assert await reg.try_reserve() is True
    assert reg.max_connections == 2


async def test_release_slot_never_goes_negative():
    reg = WsRegistry(max_connections=1)
    await reg.release_slot()
    await reg.release_slot()
    assert await reg.try_reserve() is True
    assert await reg.try_reserve() is False


async def test_register_returns_previous_connection():
    reg = WsRegistry(max_connections=10)
    old = _conn("old", "alice")
    new = _conn("new", "alice")
    assert await reg.register("alice", old) is None
    assert await reg.register("alice", new) is old
    assert reg.get("alice") is new


async def test_remove_is_guarded_by_conn_id():
    reg = WsRegistry(max_connections=10)
    first = _conn("c1", "alice")
    second = _conn("c2", "alice")
    await reg.register("alice", first)
    await reg.register("alice", second)

    # A stale (superseded) disconnect must never evict the replacement.
    await reg.remove("alice", "c1")
    assert reg.get("alice") is second

    await reg.remove("alice", "c2")
    assert reg.get("alice") is None


class _FakeWS:
    def __init__(self):
        self.closed = None

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


async def test_close_all_closes_everything_and_resets():
    reg = WsRegistry(max_connections=10)
    ws_a, ws_b = _FakeWS(), _FakeWS()
    await reg.register("alice", _conn("c1", "alice", ws_a))
    await reg.register("bob", _conn("c2", "bob", ws_b))

    await reg.close_all(code=1001, reason="down")

    assert ws_a.closed == (1001, "down")
    assert ws_b.closed == (1001, "down")
    assert reg.get("alice") is None
    assert reg.get("bob") is None


async def test_close_all_swallows_close_errors():
    class _BrokenWS:
        async def close(self, *args, **kwargs):
            raise RuntimeError("transport gone")

    reg = WsRegistry(max_connections=10)
    await reg.register("alice", _conn("c1", "alice", _BrokenWS()))
    await reg.close_all()  # must not raise

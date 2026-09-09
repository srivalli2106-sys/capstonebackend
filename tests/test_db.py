"""MongoDB connection-lifecycle tests using fakes (no running MongoDB required).

Covers the connection-layer contract of :mod:`server.db`:
* a single shared client with explicit connection/pool bounds from settings
* clean client close on shutdown
* startup health ping

Repository persistence (registration, key bundles, atomic OPK consumption) is
covered in :mod:`tests.test_repositories`.
"""

from __future__ import annotations

from server import db as db_module
from server.db import close_db, get_db, ping_mongo


def test_get_db_uses_explicit_connection_and_pool_bounds(monkeypatch):
    captured = {}

    class CapturingClient:
        def __init__(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

        def __getitem__(self, name):
            return object()

    monkeypatch.setattr(db_module, "AsyncIOMotorClient", CapturingClient)
    monkeypatch.setattr(db_module, "_client", None)

    get_db()

    assert captured["args"][0] == db_module.DATABASE_URL
    opts = captured["kwargs"]
    assert (
        opts["serverSelectionTimeoutMS"]
        == db_module.settings.mongodb_server_selection_timeout_ms
    )
    assert (
        opts["connectTimeoutMS"] == db_module.settings.mongodb_connect_timeout_ms
    )
    assert opts["socketTimeoutMS"] == db_module.settings.mongodb_socket_timeout_ms
    assert opts["maxPoolSize"] == db_module.settings.mongodb_max_pool_size
    assert opts["minPoolSize"] == db_module.settings.mongodb_min_pool_size
    assert opts["maxIdleTimeMS"] == db_module.settings.mongodb_max_idle_time_ms


def test_get_db_constructs_client_once(monkeypatch):
    created: list = []

    class CountingClient:
        def __init__(self, *args, **kwargs):
            created.append(args)

        def __getitem__(self, name):
            return object()

    monkeypatch.setattr(db_module, "AsyncIOMotorClient", CountingClient)
    monkeypatch.setattr(db_module, "_client", None)

    get_db()
    get_db()
    assert len(created) == 1


async def test_ping_mongo_issues_ping_command(monkeypatch):
    class FakeDatabase:
        def __init__(self):
            self.commands: list[str] = []

        async def command(self, op):
            self.commands.append(op)

    fake = FakeDatabase()
    monkeypatch.setattr(db_module, "get_db", lambda: fake)

    assert await ping_mongo() is True
    assert fake.commands == ["ping"]


async def test_close_db_closes_and_resets_client(monkeypatch):
    closed: list = []

    class ClosingClient:
        async def close(self):
            closed.append(1)

    monkeypatch.setattr(db_module, "_client", ClosingClient())

    await close_db()
    assert len(closed) == 1
    assert db_module._client is None


async def test_close_db_is_noop_when_never_initialized(monkeypatch):
    monkeypatch.setattr(db_module, "_client", None)
    await close_db()  # must not raise


async def test_init_db_creates_unique_indexes(monkeypatch):
    created: list[tuple] = []

    class FakeCollection:
        async def create_index(self, field, **kwargs):
            created.append((field, kwargs))

    class FakeDB:
        def __getitem__(self, name):
            return FakeCollection()

    fake = FakeDB()
    monkeypatch.setattr(db_module, "get_db", lambda: fake)

    await db_module.init_db()
    assert created == [
        ("user_id", {"unique": True}),
        ("user_id", {"unique": True}),
    ]

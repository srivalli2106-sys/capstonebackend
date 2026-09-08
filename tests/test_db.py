"""MongoDB layer tests using fakes (no running MongoDB required).

Covers the Phase 4 hardening:
* a single shared client with explicit connection/pool bounds from settings
* clean client close on shutdown
* the narrow duplicate-key-only catch in register_user (other driver errors
  propagate so they surface as dependency failures, never a false 409)
* atomic OPK consumption (find-one-and-update guarded on an unconsumed OPK,
  BEFORE return) so concurrent consumers cannot receive the same key
"""

from __future__ import annotations

import pytest
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

from server import db as db_module
from server.db import close_db, consume_opk, get_db, ping_mongo, register_user


class RecordingCollection:
    """Fake Mongo collection recording the operations performed on it."""

    def __init__(self, fau_result=None, insert_error=None):
        self.fau_result = fau_result
        self.insert_error = insert_error
        self.find_one_and_update_calls: list[tuple] = []

    async def insert_one(self, doc):
        if self.insert_error is not None:
            raise self.insert_error

    async def find_one_and_update(self, filter_, update, **kwargs):
        self.find_one_and_update_calls.append((filter_, update, kwargs))
        return self.fau_result


class FakeDB:
    """Minimal fake for the dict-like database handle used across db.py."""

    def __init__(self, collections):
        self._collections = collections

    def __getitem__(self, name):
        return self._collections[name]


def _monkeypatch_db(monkeypatch, collections):
    monkeypatch.setattr(db_module, "get_db", lambda: FakeDB(collections))


# ---------------------------------------------------------------------------
# Client lifecycle
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# register_user
# ---------------------------------------------------------------------------


async def test_register_user_duplicate_key_returns_false(monkeypatch):
    col = RecordingCollection(
        insert_error=DuplicateKeyError("E11000 duplicate key error")
    )
    _monkeypatch_db(monkeypatch, {"users": col})

    assert await register_user("alice", b"\x00" * 32) is False


async def test_register_user_propagates_non_duplicate_driver_errors(monkeypatch):
    col = RecordingCollection(insert_error=PyMongoError("network unreachable"))
    _monkeypatch_db(monkeypatch, {"users": col})

    with pytest.raises(PyMongoError):
        await register_user("alice", b"\x00" * 32)


# ---------------------------------------------------------------------------
# consume_opk (atomic)
# ---------------------------------------------------------------------------


async def test_consume_opk_atomic_call_shape(monkeypatch):
    opk = b"\x11" * 32
    col = RecordingCollection(fau_result={"user_id": "u1", "opk_public": opk})
    _monkeypatch_db(monkeypatch, {"key_bundles": col})

    result = await consume_opk("u1")
    assert result == opk

    filter_, update, kwargs = col.find_one_and_update_calls[0]
    assert filter_ == {
        "user_id": "u1",
        "opk_public": {"$exists": True, "$ne": None},
    }
    assert update == {"$set": {"opk_public": None}}
    assert kwargs["return_document"] is ReturnDocument.BEFORE


async def test_consume_opk_returns_none_when_no_opk_available(monkeypatch):
    col = RecordingCollection(fau_result=None)
    _monkeypatch_db(monkeypatch, {"key_bundles": col})

    assert await consume_opk("u1") is None
    assert len(col.find_one_and_update_calls) == 1

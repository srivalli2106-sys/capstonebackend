"""Repository layer tests using fakes (no MongoDB/Redis required).

Each test stubs the repository module's ``get_db``/``get_redis`` import so the
exact persistence mechanics (keys written, TTLs applied, atomic OPK
``find_one_and_update``, bounded frame keys) are pinned without an external
driver.
"""

from __future__ import annotations

from pymongo.errors import DuplicateKeyError

from server.config import settings
from server.repositories import message_repository as mr_module
from server.repositories import presence_repository as pr_module
from server.repositories import user_repository as ur_module
from server.repositories.key_repository import key_repository
from server.repositories.message_repository import message_repository
from server.repositories.presence_repository import presence_repository
from server.repositories.user_repository import user_repository

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeUsers:
    def __init__(self):
        self.docs: dict[str, dict] = {}

    async def insert_one(self, doc):
        if doc["user_id"] in self.docs:
            raise DuplicateKeyError("duplicate user_id")
        self.docs[doc["user_id"]] = dict(doc)

    async def find_one(self, query):
        return self.docs.get(query["user_id"])


class _FakeKeyBundles:
    def __init__(self):
        self.docs: dict[str, dict] = {}

    async def find_one(self, query):
        return self.docs.get(query["user_id"])

    async def insert_one(self, doc):
        self.docs[doc["user_id"]] = dict(doc)

    async def update_one(self, filt, update):
        doc = self.docs[filt["user_id"]]
        doc.update(update["$set"])

    async def find_one_and_update(self, filt, update, return_document):
        doc = self.docs.get(filt["user_id"])
        if doc is None:
            return None
        # Mirror the repo's semantic filter: an OPK must exist and not be None.
        if not doc.get("opk_public"):
            return None
        before = dict(doc)
        doc["opk_public"] = update["$set"]["opk_public"]
        return before


class _FakeDB:
    def __init__(self, users=None, bundles=None):
        self._users = users or _FakeUsers()
        self._bundles = bundles or _FakeKeyBundles()

    def __getitem__(self, name):
        return {"users": self._users, "key_bundles": self._bundles}[name]


class _FakeRedis:
    def __init__(self):
        self.data: dict = {}
        self.opts: dict[str, dict] = {}

    async def set(self, name, value, ex=None):
        self.data[name] = value
        self.opts[name] = {"ex": ex}

    async def exists(self, name):
        return 1 if name in self.data else 0

    async def delete(self, name):
        self.data.pop(name, None)

    async def get(self, name):
        return self.data.get(name)

    async def rpush(self, name, *values):
        self.data.setdefault(name, []).extend(values)

    async def lpop(self, name):
        vals = self.data.get(name, [])
        if not vals:
            return None
        return vals.pop(0)


# ---------------------------------------------------------------------------
# user_repository
# ---------------------------------------------------------------------------


async def test_register_user_inserts_document(monkeypatch):
    fake = _FakeUsers()
    monkeypatch.setattr(ur_module, "get_db", lambda: _FakeDB(users=fake))

    ok = await user_repository.register_user("alice", b"\x01" * 32)

    assert ok is True
    doc = fake.docs["alice"]
    assert doc["ik_public"] == b"\x01" * 32
    assert doc["created_at"] is not None


async def test_register_user_duplicate_returns_false(monkeypatch):
    fake = _FakeUsers()
    monkeypatch.setattr(ur_module, "get_db", lambda: _FakeDB(users=fake))
    await user_repository.register_user("alice", b"\x01" * 32)

    ok = await user_repository.register_user("alice", b"\x02" * 32)

    assert ok is False
    assert len(fake.docs) == 1


async def test_get_user_returns_document_or_none(monkeypatch):
    fake = _FakeUsers()
    monkeypatch.setattr(ur_module, "get_db", lambda: _FakeDB(users=fake))
    await user_repository.register_user("alice", b"\x01" * 32)

    assert (await user_repository.get_user("alice"))["user_id"] == "alice"
    assert await user_repository.get_user("ghost") is None


# ---------------------------------------------------------------------------
# key_repository
# ---------------------------------------------------------------------------


async def test_upsert_key_bundle_inserts_new_bundle(monkeypatch):
    fake = _FakeKeyBundles()
    monkeypatch.setattr("server.repositories.key_repository.get_db", lambda: _FakeDB(bundles=fake))

    await key_repository.upsert_key_bundle(
        "alice", b"\x00" * 32, b"\x01" * 32, b"\x02" * 64, None
    )

    doc = fake.docs["alice"]
    assert doc["xdh_public"] == b"\x00" * 32
    assert doc["spk_public"] == b"\x01" * 32
    assert doc["spk_sig"] == b"\x02" * 64
    assert doc["opk_public"] is None
    assert doc["version"] == 1


async def test_upsert_key_bundle_bumps_version_on_update(monkeypatch):
    fake = _FakeKeyBundles()
    monkeypatch.setattr("server.repositories.key_repository.get_db", lambda: _FakeDB(bundles=fake))
    await key_repository.upsert_key_bundle(
        "alice", b"\x00" * 32, b"\x01" * 32, b"\x02" * 64, None
    )

    await key_repository.upsert_key_bundle(
        "alice", b"\x06" * 32, b"\x03" * 32, b"\x04" * 64, b"\x05" * 32
    )

    doc = fake.docs["alice"]
    assert doc["xdh_public"] == b"\x06" * 32
    assert doc["spk_public"] == b"\x03" * 32
    assert doc["opk_public"] == b"\x05" * 32
    assert doc["version"] == 2


async def test_get_key_bundle_returns_document_or_none(monkeypatch):
    fake = _FakeKeyBundles()
    monkeypatch.setattr("server.repositories.key_repository.get_db", lambda: _FakeDB(bundles=fake))
    await key_repository.upsert_key_bundle(
        "alice", b"\x00" * 32, b"\x01" * 32, b"\x02" * 64, None
    )

    assert (await key_repository.get_key_bundle("alice"))["user_id"] == "alice"
    assert await key_repository.get_key_bundle("ghost") is None


async def test_consume_opk_returns_key_and_nulls_it_atomically(monkeypatch):
    fake = _FakeKeyBundles()
    monkeypatch.setattr("server.repositories.key_repository.get_db", lambda: _FakeDB(bundles=fake))
    opk = b"\x77" * 32
    await key_repository.upsert_key_bundle(
        "alice", b"\x00" * 32, b"\x01" * 32, b"\x02" * 64, opk
    )

    assert await key_repository.consume_opk("alice") == opk
    assert fake.docs["alice"]["opk_public"] is None
    # Second consumption finds no OPK -> None.
    assert await key_repository.consume_opk("alice") is None


async def test_consume_opk_with_no_opk_returns_none(monkeypatch):
    fake = _FakeKeyBundles()
    monkeypatch.setattr("server.repositories.key_repository.get_db", lambda: _FakeDB(bundles=fake))
    await key_repository.upsert_key_bundle(
        "alice", b"\x00" * 32, b"\x01" * 32, b"\x02" * 64, None
    )

    assert await key_repository.consume_opk("alice") is None


def _patch_redis(monkeypatch, module, fake) -> None:
    async def _get_redis():
        return fake

    monkeypatch.setattr(module, "get_redis", _get_redis)


# ---------------------------------------------------------------------------
# presence_repository
# ---------------------------------------------------------------------------


async def test_set_online_uses_configured_ttl(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, pr_module, fake)

    await presence_repository.set_online("alice")

    assert fake.data["online:alice"] == "1"
    assert fake.opts["online:alice"]["ex"] == settings.ws_presence_ttl_seconds


async def test_set_offline_deletes_online_marker(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, pr_module, fake)
    await presence_repository.set_online("alice")

    await presence_repository.set_offline("alice")

    assert "online:alice" not in fake.data


async def test_is_online_reflects_marker(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, pr_module, fake)

    assert await presence_repository.is_online("alice") is False
    await presence_repository.set_online("alice")
    assert await presence_repository.is_online("alice") is True


async def test_register_connection_uses_configured_ttl(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, pr_module, fake)

    await presence_repository.register_connection("alice", "c1")

    assert fake.data["conn:alice"] == "c1"
    assert fake.opts["conn:alice"]["ex"] == settings.ws_presence_ttl_seconds


async def test_connection_marker_get_and_remove(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, pr_module, fake)

    assert await presence_repository.get_connection("alice") is None
    await presence_repository.register_connection("alice", "c1")
    assert await presence_repository.get_connection("alice") == "c1"

    await presence_repository.remove_connection("alice")
    assert await presence_repository.get_connection("alice") is None


# ---------------------------------------------------------------------------
# message_repository
# ---------------------------------------------------------------------------


async def test_enqueue_and_dequeue_all_round_trip_in_order(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, mr_module, fake)

    await message_repository.enqueue_message("alice", "m1")
    await message_repository.enqueue_message("alice", "m2")

    assert await message_repository.dequeue_all_messages("alice") == ["m1", "m2"]
    assert "pending:alice" in fake.data
    # The key is not deleted, but drained: late enqueues after a drain are
    # popped next time (lpop returns None only when the list is empty).
    assert await message_repository.dequeue_all_messages("alice") == []


async def test_dequeue_all_empty_returns_empty(monkeypatch):
    fake = _FakeRedis()
    _patch_redis(monkeypatch, mr_module, fake)

    assert await message_repository.dequeue_all_messages("ghost") == []

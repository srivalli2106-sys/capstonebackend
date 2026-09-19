"""HTTP contract tests for the /presence endpoint (no external infrastructure).

The online/offline decision lives in ``presence_repository`` (unit-tested in
test_presence_service.py / test_repositories.py); these tests drive the real
route through the wire with a fake repository, pinning the HTTP surface:
the response shape, the ``presence`` rate-limit category, graceful degradation
to offline when Redis is unavailable, and the authentication contract.
"""

from __future__ import annotations

from server.middleware import create_token


class _FakePresence:
    def __init__(self):
        self.calls: list[str] = []
        self.online = False
        self.fail = False

    async def is_online(self, user_id: str) -> bool:
        self.calls.append(user_id)
        if self.fail:
            raise RuntimeError("redis down")
        return self.online


def _env(client, monkeypatch, fake: _FakePresence, recorded: list[str]):
    token = create_token("alice")
    headers = {"Authorization": f"Bearer {token}"}

    async def _not_revoked(jti: str) -> bool:
        return False

    async def _record(request, category: str = "general"):
        recorded.append(category)

    monkeypatch.setattr("server.routes.presence.presence_repository", fake)
    monkeypatch.setattr("server.auth_service.auth_store.is_token_revoked", _not_revoked)
    monkeypatch.setattr("server.routes.presence.check_rate_limit", _record)
    return headers


def test_presence_online(client, monkeypatch):
    fake = _FakePresence()
    fake.online = True
    recorded: list[str] = []
    headers = _env(client, monkeypatch, fake, recorded)

    resp = client.get("/presence/carol", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"user_id": "carol", "online": True}
    assert fake.calls == ["carol"]
    assert recorded == ["presence"]


def test_presence_offline(client, monkeypatch):
    fake = _FakePresence()
    fake.online = False
    headers = _env(client, monkeypatch, fake, [])

    resp = client.get("/presence/carol", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"user_id": "carol", "online": False}


def test_presence_unknown_target_reports_offline(client, monkeypatch):
    fake = _FakePresence()
    fake.online = False
    headers = _env(client, monkeypatch, fake, [])

    resp = client.get("/presence/nosuch-user", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"user_id": "nosuch-user", "online": False}


def test_presence_degrades_to_offline_when_redis_down(client, monkeypatch):
    fake = _FakePresence()
    fake.fail = True
    headers = _env(client, monkeypatch, fake, [])

    # Must NOT leak a 500: presence is non-security state and degrades to
    # an honest "offline" answer instead.
    resp = client.get("/presence/carol", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"user_id": "carol", "online": False}


def test_presence_requires_auth(client, monkeypatch):
    fake = _FakePresence()
    _env(client, monkeypatch, fake, [])

    resp = client.get("/presence/carol")
    assert resp.status_code == 401
    assert fake.calls == []

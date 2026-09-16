"""HTTP contract tests for the /keys endpoints (no external infrastructure).

The key business rules live in :class:`server.services.key_service.KeyService`
(unit-tested in test_key_service.py); these tests drive the real route through
the wire with a fake key service and a neutralized revocation read, pinning the
HTTP surface: response shapes, the rate-limit category, and the 404 contract
for unknown targets.
"""

from __future__ import annotations

from server.exceptions import ResourceNotFound
from server.middleware import create_token

_IK = ("ab" * 32)
_SPK = ("cd" * 32)
_SIG = ("ef" * 32)
_OPK = ("77" * 32)


class _FakeKeyService:
    def __init__(self):
        self.uploaded: tuple | None = None
        self.get_bundle_calls: list[str] = []
        self.opk_status_calls: list[str] = []
        self.bundle_404 = False
        self.status_404 = False

    async def upload(self, user_id, spk_public_hex, spk_sig_hex, opk_public_hex):
        self.uploaded = (user_id, spk_public_hex, spk_sig_hex, opk_public_hex)

    async def get_bundle(self, target_user_id: str) -> dict:
        self.get_bundle_calls.append(target_user_id)
        if self.bundle_404:
            raise ResourceNotFound("Key bundle not found")
        return {
            "user_id": target_user_id,
            "spk_public": _SPK,
            "spk_sig": _SIG,
            "opk_public": _OPK,
            "version": 3,
        }

    async def opk_status(self, target_user_id: str) -> dict:
        self.opk_status_calls.append(target_user_id)
        if self.status_404:
            raise ResourceNotFound("Key bundle not found")
        return {
            "user_id": target_user_id,
            "opk_available": True,
            "version": 3,
        }


def _env(client, monkeypatch, fake: _FakeKeyService, recorded: list[str]):
    token = create_token("alice")
    headers = {"Authorization": f"Bearer {token}"}

    async def _not_revoked(jti: str) -> bool:
        return False

    async def _record(request, category: str = "general"):
        recorded.append(category)

    monkeypatch.setattr("server.routes.keys.key_service", fake)
    monkeypatch.setattr(
        "server.auth_service.auth_store.is_token_revoked", _not_revoked
    )
    monkeypatch.setattr("server.routes.keys.check_rate_limit", _record)
    return headers


def test_upload_returns_ok_and_applies_keys_category(client, monkeypatch):
    fake = _FakeKeyService()
    recorded: list[str] = []
    headers = _env(client, monkeypatch, fake, recorded)

    resp = client.post(
        "/keys/upload",
        json={"spk_public": _SPK, "spk_sig": _SIG, "opk_public": _OPK},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "user_id": "alice"}
    assert fake.uploaded == ("alice", _SPK, _SIG, _OPK)
    assert recorded == ["keys"]


def test_get_bundle_returns_response_shape(client, monkeypatch):
    fake = _FakeKeyService()
    recorded: list[str] = []
    headers = _env(client, monkeypatch, fake, recorded)

    resp = client.get("/keys/bundle/carol", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "user_id": "carol",
        "spk_public": _SPK,
        "spk_sig": _SIG,
        "opk_public": _OPK,
        "version": 3,
    }
    assert fake.get_bundle_calls == ["carol"]
    assert recorded == ["keys"]


def test_get_bundle_unknown_target_is_404_contract(client, monkeypatch):
    fake = _FakeKeyService()
    fake.bundle_404 = True
    headers = _env(client, monkeypatch, fake, [])

    resp = client.get("/keys/bundle/nosuch", headers=headers)
    assert resp.status_code == 404
    body = resp.json()["error"]
    assert body["code"] == "not_found"
    assert body["message"] == "Key bundle not found"
    assert body["request_id"] == resp.headers.get("x-request-id")


def test_opk_status_returns_availability(client, monkeypatch):
    fake = _FakeKeyService()
    recorded: list[str] = []
    headers = _env(client, monkeypatch, fake, recorded)

    resp = client.get("/keys/prekeys/carol", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "user_id": "carol",
        "opk_available": True,
        "version": 3,
    }
    assert fake.opk_status_calls == ["carol"]
    assert recorded == ["keys"]


def test_prekeys_unknown_target_is_404_contract(client, monkeypatch):
    fake = _FakeKeyService()
    fake.status_404 = True
    headers = _env(client, monkeypatch, fake, [])

    resp = client.get("/keys/prekeys/nosuch", headers=headers)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"

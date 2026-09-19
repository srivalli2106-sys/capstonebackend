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

_XDH = ("aa" * 32)
_IK = ("ab" * 32)
_SPK = ("cd" * 32)
_SIG = ("ef" * 64)  # 64-byte Ed25519 signature = 128 hex chars
_OPK = ("77" * 32)


class _FakeKeyService:
    def __init__(self):
        self.uploaded: tuple | None = None
        self.get_bundle_calls: list[str] = []
        self.opk_status_calls: list[str] = []
        self.bundle_404 = False
        self.status_404 = False

    async def upload(
        self,
        user_id,
        xdh_public_hex,
        spk_public_hex,
        spk_sig_hex,
        opk_public_hex,
        pq_kem_public_hex=None,
        pq_sig_public_hex=None,
        pq_binding_sig_hex=None,
        protocol_version=1,
    ):
        self.uploaded = (
            user_id,
            xdh_public_hex,
            spk_public_hex,
            spk_sig_hex,
            opk_public_hex,
            pq_kem_public_hex,
            pq_sig_public_hex,
            pq_binding_sig_hex,
            protocol_version,
        )

    async def get_bundle(self, target_user_id: str) -> dict:
        self.get_bundle_calls.append(target_user_id)
        if self.bundle_404:
            raise ResourceNotFound("Key bundle not found")
        return {
            "user_id": target_user_id,
            "ik_public": _IK,
            "xdh_public": _XDH,
            "spk_public": _SPK,
            "spk_sig": _SIG,
            "opk_public": _OPK,
            "pq_kem_public": None,
            "pq_sig_public": None,
            "pq_binding_sig": None,
            "protocol_version": 1,
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
        json={
            "xdh_public": _XDH,
            "spk_public": _SPK,
            "spk_sig": _SIG,
            "opk_public": _OPK,
        },
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "user_id": "alice"}
    assert fake.uploaded == (
        "alice", _XDH, _SPK, _SIG, _OPK, None, None, None, 1
    )
    assert recorded == ["keys"]


def test_upload_accepts_128_character_ed25519_signature(client, monkeypatch):
    """Blocker 1: a real 128-hex-char Ed25519 signature must be accepted.

    The previous 64-hex-char cap on ``spk_sig`` incorrectly rejected every
    valid 64-byte (128-hex) signature. This test pins the new min/max so the
    fix cannot regress.
    """
    fake = _FakeKeyService()
    headers = _env(client, monkeypatch, fake, [])

    sig_128 = "ef" * 64  # exactly 128 hex chars = 64 bytes

    resp = client.post(
        "/keys/upload",
        json={
            "xdh_public": _XDH,
            "spk_public": _SPK,
            "spk_sig": sig_128,
            "opk_public": _OPK,
        },
        headers=headers,
    )

    assert resp.status_code == 200
    assert fake.uploaded[3] == sig_128


def test_upload_rejects_short_signature(client, monkeypatch):
    """Blocker 1: shorter-than-128-hex signatures are rejected by validation."""
    fake = _FakeKeyService()
    headers = _env(client, monkeypatch, fake, [])

    sig_short = "ef" * 32  # only 64 hex chars

    resp = client.post(
        "/keys/upload",
        json={
            "xdh_public": _XDH,
            "spk_public": _SPK,
            "spk_sig": sig_short,
            "opk_public": _OPK,
        },
        headers=headers,
    )

    assert resp.status_code == 422


def test_upload_rejects_oversized_signature(client, monkeypatch):
    """Blocker 1: signatures longer than 128 hex chars are still rejected."""
    fake = _FakeKeyService()
    headers = _env(client, monkeypatch, fake, [])

    sig_long = "ef" * 65  # 130 hex chars

    resp = client.post(
        "/keys/upload",
        json={
            "xdh_public": _XDH,
            "spk_public": _SPK,
            "spk_sig": sig_long,
            "opk_public": _OPK,
        },
        headers=headers,
    )

    assert resp.status_code == 422


def test_get_bundle_includes_xdh_public(client, monkeypatch):
    """Blocker 2: the response carries the X25519 X3DH identity (``xdh_public``)."""
    fake = _FakeKeyService()
    recorded: list[str] = []
    headers = _env(client, monkeypatch, fake, recorded)

    resp = client.get("/keys/bundle/carol", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "user_id": "carol",
        "ik_public": _IK,
        "xdh_public": _XDH,
        "spk_public": _SPK,
        "spk_sig": _SIG,
        "opk_public": _OPK,
        "pq_kem_public": None,
        "pq_sig_public": None,
        "pq_binding_sig": None,
        "protocol_version": 1,
    }
    # xdh_public is a 32-byte X25519 public key = 64 hex chars.
    assert len(body["xdh_public"]) == 64
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

"""
End-to-end auth + keys flow tests.

Require MongoDB (unique index on user_id) and Redis. Rate limiting is
neutralized by the integration conftest so that one-time registration
(1 request/hour/IP) does not mask the flows under test.
"""

from __future__ import annotations

import pytest

from server.middleware import create_token

pytestmark = pytest.mark.integration

IK = "ab" * 32          # valid 32-byte identity key (hex)
XDH = "ab" * 32         # valid 32-byte X3DH X25519 identity (hex)
SPK = "cd" * 32         # valid 32-byte signed prekey (hex)
SIG = "ef" * 64         # valid 64-byte Ed25519 prekey signature (hex)
OPK = "12" * 32         # valid 32-byte one-time prekey (hex)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# /auth
# ---------------------------------------------------------------------------


def test_register_login_and_duplicate_rejected(client):
    r = client.post("/auth/register", json={"user_id": "alice", "ik_public": IK})
    assert r.status_code == 201
    assert r.json() == {"status": "registered", "user_id": "alice"}

    dup = client.post("/auth/register", json={"user_id": "alice", "ik_public": IK})
    assert dup.status_code == 409

    login = client.post("/auth/login", json={"user_id": "alice"})
    assert login.status_code == 200
    body = login.json()
    assert body["user_id"] == "alice"
    assert isinstance(body["token"], str) and body["token"]

    missing = client.post("/auth/login", json={"user_id": "ghost"})
    assert missing.status_code == 404


def test_register_validation_rejections(client):
    bad_hex = client.post(
        "/auth/register", json={"user_id": "v_hex", "ik_public": "zz"}
    )
    assert bad_hex.status_code == 400

    short_key = client.post(
        "/auth/register", json={"user_id": "v_short", "ik_public": "ab"}
    )
    assert short_key.status_code == 400

    short_id = client.post(
        "/auth/register", json={"user_id": "x", "ik_public": IK}
    )
    assert short_id.status_code == 400


# ---------------------------------------------------------------------------
# /keys
# ---------------------------------------------------------------------------


def test_keys_upload_fetch_and_opk_consumption(client):
    uid = "carol"
    assert client.post(
        "/auth/register", json={"user_id": uid, "ik_public": IK}
    ).status_code == 201
    headers = _auth(create_token(uid))

    # Auth is required.
    assert client.post(
        "/keys/upload",
        json={
            "xdh_public": XDH,
            "spk_public": SPK,
            "spk_sig": SIG,
            "opk_public": OPK,
        },
    ).status_code == 401

    # Bad hex / wrong length are rejected before touching the DB.
    assert client.post(
        "/keys/upload",
        json={"xdh_public": XDH, "spk_public": "zz", "spk_sig": SIG},
        headers=headers,
    ).status_code == 400
    assert client.post(
        "/keys/upload",
        json={"xdh_public": XDH, "spk_public": "abcd", "spk_sig": SIG},
        headers=headers,
    ).status_code == 400

    # Valid upload.
    upload = client.post(
        "/keys/upload",
        json={
            "xdh_public": XDH,
            "spk_public": SPK,
            "spk_sig": SIG,
            "opk_public": OPK,
        },
        headers=headers,
    )
    assert upload.status_code == 200
    assert upload.json() == {"status": "ok", "user_id": uid}

    # Fetching the bundle consumes the OPK and serves it exactly once: the
    # response carries the fresh one-time prekey, the store is left null, and
    # any later fetch/status call sees it as consumed.
    bundle = client.get(f"/keys/bundle/{uid}", headers=headers)
    assert bundle.status_code == 200
    body = bundle.json()
    assert body["user_id"] == uid
    assert body["xdh_public"] == XDH
    assert body["spk_public"] == SPK
    assert body["opk_public"] == OPK

    # Re-fetch still works.
    assert client.get(f"/keys/bundle/{uid}", headers=headers).status_code == 200

    # OPK status reports it as consumed.
    status = client.get(f"/keys/prekeys/{uid}", headers=headers)
    assert status.status_code == 200
    assert status.json()["opk_available"] is False

    # Unknown target.
    assert client.get("/keys/bundle/nosuchuser", headers=headers).status_code == 404

"""
End-to-end proof-of-possession (Ed25519 challenge/verify) flow tests.

Require MongoDB (unique index on user_id) and Redis. Rate limiting is
neutralized by the integration conftest. Unique user_ids keep repeat runs
(against a persistent DB) from colliding on duplicate registration.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.integration

SPK = "cd" * 32  # valid 32-byte signed prekey (hex)
SIG = "ef" * 32  # valid 32-byte prekey signature (hex)
OPK = "12" * 32  # valid 32-byte one-time prekey (hex)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _register(client, uid: str) -> Ed25519PrivateKey:
    private = Ed25519PrivateKey.generate()
    ik_pub = private.public_key().public_bytes_raw().hex()
    resp = client.post("/auth/register", json={"user_id": uid, "ik_public": ik_pub})
    assert resp.status_code == 201
    return private


def test_proof_of_possession_auth_flow(client):
    uid = f"dave_{uuid.uuid4().hex[:8]}"
    private = _register(client, uid)

    # Server issues a fresh 32-byte nonce bound to the user.
    challenge = client.post("/auth/challenge", json={"user_id": uid})
    assert challenge.status_code == 200
    nonce = challenge.json()["nonce"]
    assert len(nonce) == 64 and len(bytes.fromhex(nonce)) == 32

    # Signing the nonce with the registered identity key proves possession.
    signature = private.sign(bytes.fromhex(nonce)).hex()
    verify = client.post(
        "/auth/verify",
        json={"user_id": uid, "nonce": nonce, "signature": signature},
    )
    assert verify.status_code == 200
    token = verify.json()["token"]
    assert verify.json()["user_id"] == uid

    # The challenge is single-use: replaying it fails.
    replay = client.post(
        "/auth/verify",
        json={"user_id": uid, "nonce": nonce, "signature": signature},
    )
    assert replay.status_code == 401

    # The JWT is accepted on protected routes.
    headers = _auth(token)
    upload = client.post(
        "/keys/upload",
        json={"spk_public": SPK, "spk_sig": SIG, "opk_public": OPK},
        headers=headers,
    )
    assert upload.status_code == 200

    # Logout revokes the token server-side.
    logout = client.post("/auth/logout", headers=headers)
    assert logout.status_code == 200

    # The revoked token is refused on protected routes and logout.
    assert client.get(f"/keys/prekeys/{uid}", headers=headers).status_code == 401
    assert client.post("/auth/logout", headers=headers).status_code == 401


def test_proof_of_possession_rejects_wrong_key(client):
    uid = f"mallory_{uuid.uuid4().hex[:8]}"
    registered = _register(client, uid)

    # Challenge is announced publicly; the attacker does not hold the private key.
    challenge = client.post("/auth/challenge", json={"user_id": uid})
    nonce = challenge.json()["nonce"]
    assert challenge.status_code == 200

    attacker_wrong_sig = Ed25519PrivateKey.generate().sign(bytes.fromhex(nonce)).hex()
    verify = client.post(
        "/auth/verify",
        json={"user_id": uid, "nonce": nonce, "signature": attacker_wrong_sig},
    )
    assert verify.status_code == 401
    assert verify.json()["error"]["message"] == "Authentication failed"

    # The challenge is consumed by the failed attempt (single-use, fail-closed):
    # even the holder of the correct key cannot reuse the spent nonce.
    good_sig = registered.sign(bytes.fromhex(nonce)).hex()
    retry = client.post(
        "/auth/verify",
        json={"user_id": uid, "nonce": nonce, "signature": good_sig},
    )
    assert retry.status_code == 401

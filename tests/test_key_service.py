"""KeyService business-rule tests (no infra required).

Fakes implement the ``UserRepository``/``KeyRepository`` protocols; the tests
pin the pre-refactor HTTP contract for /keys/upload, /keys/bundle, and
/keys/prekeys.
"""

from __future__ import annotations

import pytest

from server.exceptions import InvalidRequest, ResourceNotFound
from server.services.key_service import KeyService

_XDH = ("aa" * 32)
_SPK = ("cd" * 32)
_SIG = ("ef" * 64)  # 64-byte Ed25519 signature = 128 hex chars
_OPK = ("77" * 32)


class _Users:
    def __init__(self, registered: bool = True):
        self.registered = registered

    async def get_user(self, user_id: str) -> dict | None:
        return _user(user_id) if self.registered else None

    async def register_user(self, user_id: str, ik_public: bytes) -> bool:
        raise NotImplementedError


class _Keys:
    def __init__(self, bundle: dict | None = None):
        self.bundle = bundle
        self.consumed: list[str] = []

    async def upsert_key_bundle(
        self,
        user_id,
        xdh_public,
        spk_public,
        spk_sig,
        opk_public,
        pq_kem_public=None,
        pq_sig_public=None,
        pq_binding_sig=None,
        protocol_version=1,
    ):
        self.uploaded = (
            user_id,
            xdh_public,
            spk_public,
            spk_sig,
            opk_public,
            pq_kem_public,
            pq_sig_public,
            pq_binding_sig,
            protocol_version,
        )

    async def get_key_bundle(self, user_id: str) -> dict | None:
        return self.bundle

    async def consume_opk(self, user_id: str) -> bytes | None:
        self.consumed.append(user_id)
        opk = self.bundle.get("opk_public") if self.bundle else None
        if self.bundle is not None:
            self.bundle["opk_public"] = None
        return opk


def _bundle(opk=None, version=1):
    return {
        "user_id": "carol",
        "xdh_public": b"\xaa" * 32,
        "spk_public": b"\xcd" * 32,
        "spk_sig": b"\xef" * 64,
        "opk_public": opk,
        "version": version,
    }


def _user(bundle_owner_id: str) -> dict:
    return {"user_id": bundle_owner_id, "ik_public": b"\xbb" * 32}


# ---------------------------------------------------------------------------
# upload
# ---------------------------------------------------------------------------


async def test_upload_unknown_user_raises_not_found():
    svc = KeyService(users=_Users(registered=False), keys=_Keys())
    with pytest.raises(ResourceNotFound) as exc:
        await svc.upload("carol", _XDH, _SPK, _SIG, _OPK)
    assert exc.value.message == "User not found. Register first."


async def test_upload_rejects_non_hex_keys():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", "zz", _SPK, _SIG, _OPK)
    assert exc.value.message == "xdh_public, spk_public, and spk_sig must be hex"


async def test_upload_rejects_non_hex_signature():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", _XDH, _SPK, "zz", _OPK)
    assert exc.value.message == "xdh_public, spk_public, and spk_sig must be hex"


async def test_upload_rejects_wrong_xdh_length():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", "aa" * 31, _SPK, _SIG, _OPK)
    assert exc.value.message == "xdh_public must be 32 bytes"


async def test_upload_rejects_wrong_spk_length():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", _XDH, "cd" * 31, _SIG, _OPK)
    assert exc.value.message == "spk_public must be 32 bytes"


async def test_upload_rejects_short_signature():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", _XDH, _SPK, "ef" * 32, _OPK)
    assert exc.value.message == "spk_sig must be 64 bytes"


async def test_upload_rejects_long_signature():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", _XDH, _SPK, "ef" * 65, _OPK)
    assert exc.value.message == "spk_sig must be 64 bytes"


async def test_upload_rejects_non_hex_opk():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", _XDH, _SPK, _SIG, "zz")
    assert exc.value.message == "opk_public must be hex"


async def test_upload_rejects_wrong_opk_length():
    svc = KeyService(users=_Users(), keys=_Keys())
    with pytest.raises(InvalidRequest) as exc:
        await svc.upload("carol", _XDH, _SPK, _SIG, "77" * 31)
    assert exc.value.message == "opk_public must be 32 bytes"


async def test_upload_without_opk_passes_none():
    keys = _Keys()
    svc = KeyService(users=_Users(), keys=keys)

    result = await svc.upload("carol", _XDH, _SPK, _SIG, None)

    assert result == {"status": "ok", "user_id": "carol"}
    # First five classical fields; PQ fields default to None/version=1.
    uid, xdh, spk, sig, opk, pq_kem, pq_sig, pq_bind, version = keys.uploaded
    assert (uid, xdh, spk, sig, opk) == (
        "carol",
        b"\xaa" * 32,
        b"\xcd" * 32,
        b"\xef" * 64,
        None,
    )
    assert pq_kem is None and pq_sig is None and pq_bind is None
    assert version == 1


# ---------------------------------------------------------------------------
# get_bundle
# ---------------------------------------------------------------------------


async def test_get_bundle_unknown_target_raises_not_found():
    svc = KeyService(users=_Users(), keys=_Keys(bundle=None))
    with pytest.raises(ResourceNotFound) as exc:
        await svc.get_bundle("ghost")
    assert exc.value.message == "Key bundle not found"


async def test_get_bundle_returns_hex_dict_and_consumes_opk_once():
    keys = _Keys(bundle=_bundle(opk=b"\x77" * 32))
    svc = KeyService(users=_Users(), keys=keys)

    result = await svc.get_bundle("carol")

    assert result == {
        "user_id": "carol",
        "ik_public": "bb" * 32,
        "xdh_public": "aa" * 32,
        "spk_public": "cd" * 32,
        "spk_sig": "ef" * 64,
        "opk_public": "77" * 32,
        "pq_kem_public": None,
        "pq_sig_public": None,
        "pq_binding_sig": None,
        "protocol_version": 1,
    }
    # OPK consumed exactly once: the winning fetch serves the fresh prekey and
    # leaves the stored value null so later fetches get nothing.
    assert keys.consumed == ["carol"]
    assert keys.bundle["opk_public"] is None


async def test_get_bundle_without_opk_returns_none():
    keys = _Keys(bundle=_bundle(opk=None))
    svc = KeyService(users=_Users(), keys=keys)

    result = await svc.get_bundle("carol")

    assert result["opk_public"] is None
    assert result["xdh_public"] == "aa" * 32


async def test_get_bundle_serves_opk_exactly_once():
    keys = _Keys(bundle=_bundle(opk=b"\x77" * 32))
    svc = KeyService(users=_Users(), keys=keys)

    first = await svc.get_bundle("carol")
    second = await svc.get_bundle("carol")

    assert first["opk_public"] == "77" * 32
    assert second["opk_public"] is None
    assert keys.consumed == ["carol", "carol"]


async def test_get_bundle_missing_user_raises_not_found():
    keys = _Keys(bundle=_bundle(opk=None))
    svc = KeyService(users=_Users(registered=False), keys=keys)
    with pytest.raises(ResourceNotFound) as exc:
        await svc.get_bundle("carol")
    assert exc.value.message == "Key bundle not found"


# ---------------------------------------------------------------------------
# opk_status
# ---------------------------------------------------------------------------


async def test_opk_status_unknown_target_raises_not_found():
    svc = KeyService(users=_Users(), keys=_Keys(bundle=None))
    with pytest.raises(ResourceNotFound):
        await svc.opk_status("ghost")


async def test_opk_status_reports_availability():
    svc = KeyService(users=_Users(), keys=_Keys(bundle=_bundle(opk=b"\x77" * 32)))
    assert (await svc.opk_status("carol"))["opk_available"] is True

    svc = KeyService(users=_Users(), keys=_Keys(bundle=_bundle(opk=None)))
    assert (await svc.opk_status("carol"))["opk_available"] is False

"""protocol.x3dh unit tests: agreement, tamper evidence, error paths."""

from __future__ import annotations

import pytest

from protocol.keys import (
    build_key_bundle,
    ed25519_public_bytes,
    generate_device_keys,
)
from protocol.x3dh import (
    NO_OPK,
    X3DHError,
    associated_data,
    pack_init_message,
    unpack_init_message,
    x3dh_initiate,
    x3dh_respond,
)


def _bundle(opk_count: int = 3):
    return build_key_bundle(generate_device_keys(opk_count=opk_count))


def test_initiator_and_responder_agree_with_one_time_prekey():
    alice = generate_device_keys()
    bob = generate_device_keys(opk_count=2)
    bob_bundle = build_key_bundle(bob)

    initiation = x3dh_initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bob_bundle,
        opk_index=1,
    )
    acceptance = x3dh_respond(bob, initiation.init_payload)

    assert initiation.shared_secret == acceptance.shared_secret
    assert initiation.ad == acceptance.ad
    assert acceptance.consumed_opk_index == 1
    assert acceptance.initiator_ik_x_public == alice_bundle_ik(alice)
    assert initiation.opk_index == 1


def test_initiator_and_responder_agree_without_one_time_prekey():
    alice = generate_device_keys()
    bob = generate_device_keys(opk_count=0)
    bob_bundle = build_key_bundle(bob)

    initiation = x3dh_initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bob_bundle,
        opk_index=None,
    )
    acceptance = x3dh_respond(bob, initiation.init_payload)

    assert initiation.shared_secret == acceptance.shared_secret
    assert acceptance.consumed_opk_index is None


def test_different_opk_yields_different_secret():
    alice = generate_device_keys()
    bob = generate_device_keys(opk_count=3)
    bob_bundle = build_key_bundle(bob)

    first = x3dh_initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bob_bundle,
        opk_index=0,
    )
    second = x3dh_initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bob_bundle,
        opk_index=2,
    )
    assert first.shared_secret != second.shared_secret


def test_initiation_rejects_invalid_opk_index():
    alice = generate_device_keys()
    bob_bundle = _bundle(opk_count=2)
    with pytest.raises(X3DHError):
        x3dh_initiate(
            alice.xdh_private,
            ed25519_public_bytes(alice.auth_private.public_key()),
            bob_bundle,
            opk_index=5,
        )
    with pytest.raises(X3DHError):
        x3dh_initiate(
            alice.xdh_private,
            ed25519_public_bytes(alice.auth_private.public_key()),
            bob_bundle,
            opk_index=-1,
        )


def test_initiation_rejects_tampered_signed_prekey():
    alice = generate_device_keys()
    bob_bundle = _bundle(opk_count=2)
    tampered = bytes([bob_bundle.spk_public[0] ^ 0xFF]) + bob_bundle.spk_public[1:]
    sneak = protocol_replace_spk(bob_bundle, tampered)
    with pytest.raises(X3DHError, match="signature"):
        x3dh_initiate(
            alice.xdh_private,
            ed25519_public_bytes(alice.auth_private.public_key()),
            sneak,
            opk_index=0,
        )


def test_respond_rejects_unavailable_opk_index():
    init = pack_init_message(b"\x01" * 32, b"\x02" * 32, 7)
    bob = generate_device_keys(opk_count=2)
    with pytest.raises(X3DHError, match="one-time"):
        x3dh_respond(bob, init)


def test_respond_rejects_malformed_payload():
    bob = generate_device_keys(opk_count=2)
    for payload in (b"", b"short", b"\x00" * 100):
        with pytest.raises(X3DHError):
            x3dh_respond(bob, payload)


def test_respond_rejects_unsupported_version():
    bob = generate_device_keys(opk_count=2)
    payload = pack_init_message(b"\x01" * 32, b"\x02" * 32, None)
    bad = bytes([0xFF]) + payload[1:]
    with pytest.raises(X3DHError, match="version"):
        x3dh_respond(bob, bad)


def test_pack_unpack_round_trip():
    packed = pack_init_message(b"\x01" * 32, b"\x02" * 32, 3)
    parsed = unpack_init_message(packed)
    assert parsed["version"] == 1
    assert parsed["ik_x_public"] == b"\x01" * 32
    assert parsed["ek_public"] == b"\x02" * 32
    assert parsed["opk_index"] == 3

    no_opk = unpack_init_message(pack_init_message(b"\x01" * 32, b"\x02" * 32, None))
    assert no_opk["opk_index"] is None
    assert no_opk["opk_index"] != NO_OPK


def test_associated_data_binds_both_identities():
    a, b = b"\x01" * 32, b"\x02" * 32
    assert associated_data(a, b) == a + b
    assert len(associated_data(a, b)) == 64
    assert associated_data(a, b) != associated_data(b, a)


def test_initiation_is_deniable_without_opk_none_case():
    alice = generate_device_keys()
    bob = generate_device_keys(opk_count=2)
    bundle = build_key_bundle(bob)
    without = x3dh_initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bundle,
        None,
    )
    with_opk = x3dh_initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bundle,
        0,
    )
    assert without.shared_secret != with_opk.shared_secret


def alice_bundle_ik(alice) -> bytes:
    from protocol.keys import x25519_public_raw

    return x25519_public_raw(alice.xdh_private)


def protocol_replace_spk(bundle, new_spk):
    from protocol.keys import KeyBundle

    return KeyBundle(
        bundle.ik_public,
        bundle.xdh_public,
        new_spk,
        bundle.spk_signature,
        bundle.opk_publics,
    )

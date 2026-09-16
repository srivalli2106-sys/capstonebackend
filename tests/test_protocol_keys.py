"""protocol.keys unit tests (pure cryptography, no infra)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from protocol.keys import (
    SPK_SIGN_CONTEXT,
    build_key_bundle,
    ed25519_public_bytes,
    ed25519_public_from_bytes,
    generate_device_keys,
    verify_signed_prekey,
    x25519_private_from_bytes,
    x25519_public_from_bytes,
    x25519_public_raw,
)


def test_device_keys_generate_expected_prekey_count():
    device = generate_device_keys(opk_count=5)
    assert len(device.opk_privates) == 5
    assert device.opk_privates[0].public_key() is not None


def test_device_keys_rejects_negative_opk_count():
    with pytest.raises(ValueError):
        generate_device_keys(opk_count=-1)


def test_bundle_matches_device_and_signature_verifies():
    device = generate_device_keys(opk_count=3)
    bundle = build_key_bundle(device)
    assert bundle.ik_public == ed25519_public_bytes(
        device.auth_private.public_key()
    )
    assert bundle.xdh_public == x25519_public_raw(device.xdh_private)
    assert bundle.spk_public == x25519_public_raw(device.spk_private)
    assert len(bundle.spk_public) == 32
    assert len(bundle.spk_signature) == 64
    assert len(bundle.opk_publics) == 3
    assert verify_signed_prekey(
        bundle.ik_public, bundle.spk_public, bundle.spk_signature
    )


def test_signature_rejects_tampered_spk():
    device = generate_device_keys()
    bundle = build_key_bundle(device)
    tampered = bytes([bundle.spk_public[0] ^ 0xFF]) + bundle.spk_public[1:]
    assert not verify_signed_prekey(
        bundle.ik_public, tampered, bundle.spk_signature
    )


def test_signature_rejects_wrong_identity():
    device = generate_device_keys()
    other = generate_device_keys()
    bundle = build_key_bundle(device)
    other_bundle = build_key_bundle(other)
    assert not verify_signed_prekey(
        other_bundle.ik_public, bundle.spk_public, bundle.spk_signature
    )


def test_signature_rejects_tampered_signature_bytes():
    device = generate_device_keys()
    bundle = build_key_bundle(device)
    bad_sig = bytes([bundle.spk_signature[0] ^ 0xFF]) + bundle.spk_signature[1:]
    assert not verify_signed_prekey(bundle.ik_public, bundle.spk_public, bad_sig)


def test_signature_context_stability():
    identity = Ed25519PrivateKey.generate()
    pub = x25519_public_raw(
        generate_device_keys().spk_private
    )
    signature = identity.sign(SPK_SIGN_CONTEXT + pub)
    assert verify_signed_prekey(
        ed25519_public_bytes(identity.public_key()), pub, signature
    )
    # A signature over a different context string must not verify.
    sneaky = identity.sign(b"other-context" + pub)
    assert not verify_signed_prekey(
        ed25519_public_bytes(identity.public_key()), pub, sneaky
    )


def test_public_hex_export():
    device = generate_device_keys(opk_count=2)
    bundle = build_key_bundle(device)
    exported = bundle.public_hex()
    assert exported["ik_public"] == bundle.ik_public.hex()
    assert exported["xdh_public"] == bundle.xdh_public.hex()
    assert exported["spk_public"] == bundle.spk_public.hex()
    assert exported["spk_signature"] == bundle.spk_signature.hex()
    assert exported["opk_publics"] == [k.hex() for k in bundle.opk_publics]


@pytest.mark.parametrize("length", [0, 31, 33])
def test_raw_key_validators_enforce_32_bytes(length):
    raw = b"\x00" * length
    with pytest.raises(ValueError):
        x25519_public_from_bytes(raw)
    with pytest.raises(ValueError):
        x25519_private_from_bytes(raw)
    with pytest.raises(ValueError):
        ed25519_public_from_bytes(raw)

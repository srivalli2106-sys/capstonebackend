"""protocol.session E2E tests: x3dh -> ratchet -> full conversation."""

from __future__ import annotations

import pytest

from protocol.keys import build_key_bundle, ed25519_public_bytes, generate_device_keys
from protocol.ratchet import DecryptionError
from protocol.session import E2EESession, SessionError


def _alice_session(bob_bundle, opk_index=0):
    alice = generate_device_keys()
    session = E2EESession.initiate(
        alice.xdh_private,
        ed25519_public_bytes(alice.auth_private.public_key()),
        bob_bundle,
        opk_index,
    )
    return alice, session


def test_full_conversation_with_one_time_prekey():
    bob = generate_device_keys(opk_count=3)
    bob_bundle = build_key_bundle(bob)
    _, alice = _alice_session(bob_bundle, opk_index=2)
    bob_session = E2EESession.accept(bob, alice.init_payload)

    init_msg = alice.encrypt_message(b"first", b"alice->bob")
    assert bob_session.decrypt_message(init_msg, b"alice->bob") == b"first"

    bob_reply = bob_session.encrypt_message(b"hi alice", b"alice->bob")
    assert alice.decrypt_message(bob_reply, b"alice->bob") == b"hi alice"

    # Later messages in both directions keep working after the ratchet turns.
    for i in range(3):
        wire = alice.encrypt_message(f"a{i}".encode(), b"")
        assert bob_session.decrypt_message(wire, b"") == f"a{i}".encode()
        wire_b = bob_session.encrypt_message(f"b{i}".encode(), b"")
        assert alice.decrypt_message(wire_b, b"") == f"b{i}".encode()


def test_extra_ad_binds_envelope_context():
    bob = generate_device_keys(opk_count=1)
    bob_bundle = build_key_bundle(bob)
    _, alice = _alice_session(bob_bundle, opk_index=0)
    bob_session = E2EESession.accept(bob, alice.init_payload)

    wire = alice.encrypt_message(b"secret", b"text bob alice")
    assert bob_session.decrypt_message(wire, b"text bob alice") == b"secret"

    # A mismatched AD fails authentication.
    wrong = alice.encrypt_message(b"y", b"text bob alice")
    with pytest.raises(DecryptionError):
        bob_session.decrypt_message(wrong, b"text alice bob")


def test_init_payload_only_on_initiator():
    bob = generate_device_keys(opk_count=1)
    bob_bundle = build_key_bundle(bob)
    _, alice = _alice_session(bob_bundle, opk_index=0)
    assert alice.init_payload
    bob_session = E2EESession.accept(bob, alice.init_payload)
    with pytest.raises(SessionError):
        _ = bob_session.init_payload


def test_session_from_wrong_bundle_cannot_decrypt():
    bob = generate_device_keys(opk_count=1)
    other_bob = generate_device_keys(opk_count=1)
    others_bundle = build_key_bundle(other_bob)
    _, alice = _alice_session(others_bundle, opk_index=0)
    wire = alice.encrypt_message(b"for-other", b"")
    impersonated = E2EESession.accept(bob, alice.init_payload)
    with pytest.raises(DecryptionError):
        impersonated.decrypt_message(wire, b"")


def test_session_state_round_trip_resumes_conversation():
    bob = generate_device_keys(opk_count=2)
    bob_bundle = build_key_bundle(bob)
    alice_device, alice = _alice_session(bob_bundle, opk_index=1)
    bob_session = E2EESession.accept(bob, alice.init_payload)

    wire = alice.encrypt_message(b"pre-restart", b"ad")
    assert bob_session.decrypt_message(wire, b"ad") == b"pre-restart"

    alice_restored = E2EESession.from_state_bytes(alice.export_state())
    bob_restored = E2EESession.from_state_bytes(bob_session.export_state())
    assert alice_restored.is_initiator
    assert not bob_restored.is_initiator

    back = bob_restored.encrypt_message(b"post-restart", b"ad")
    assert alice_restored.decrypt_message(back, b"ad") == b"post-restart"


def test_session_state_rejects_garbage():
    for payload in (b"", b"\x00" * 20, b"\xff" * 40):
        with pytest.raises(SessionError):
            E2EESession.from_state_bytes(payload)


def test_session_state_rejects_truncated_ad():
    bob = generate_device_keys(opk_count=1)
    bob_bundle = build_key_bundle(bob)
    alice_device, alice = _alice_session(bob_bundle, opk_index=0)
    blob = alice.export_state()

    # Claim one extra AD byte than is actually present (AD length is the
    # uint32 at offset 3).
    mangled = bytearray(blob)
    mangled[3:7] = (len(blob) + 1).to_bytes(4, "big")
    with pytest.raises(SessionError, match="truncated"):
        E2EESession.from_state_bytes(bytes(mangled))

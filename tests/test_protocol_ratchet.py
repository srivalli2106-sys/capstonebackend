"""protocol.ratchet unit tests: turns, reordering, replay, tamper, state."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from protocol.kdf import derive_message_key, root_chain
from protocol.keys import dh, x25519_public_raw
from protocol.ratchet import (
    _HEADER_SIZE,
    _STATE_HEADER,
    DecryptionError,
    DoubleRatchet,
    Header,
    RatchetError,
    pack_header,
    pack_message,
    unpack_header,
)


def _pair():
    """Alice(initiator) and Bob(responder) ratchets sharing one seed."""
    seed_key = b"\x5e" * 32
    alice_local = X25519PrivateKey.generate()
    bob_local = X25519PrivateKey.generate()
    bob_public = x25519_public_raw(bob_local)
    root_key, start_chain = root_chain(seed_key, dh(alice_local, bob_public))
    alice = DoubleRatchet(
        root_key, start_chain, alice_local, bob_public, initiator=True
    )
    bob = DoubleRatchet(
        root_key,
        start_chain,
        bob_local,
        x25519_public_raw(alice_local),
        initiator=False,
    )
    return alice, bob


AD = b"associated-data"


def test_initiator_sends_responder_receives():
    alice, bob = _pair()
    first = alice.encrypt_message(b"hello bob", AD)
    assert bob.decrypt_message(first, AD) == b"hello bob"


def test_responder_reply_is_decryptable_by_initiator():
    alice, bob = _pair()
    alice_first = alice.encrypt_message(b"init", AD)
    assert bob.decrypt_message(alice_first, AD) == b"init"

    bob_reply = bob.encrypt_message(b"reply", AD)
    assert alice.decrypt_message(bob_reply, AD) == b"reply"


def test_alternating_turns_stay_in_sync():
    alice, bob = _pair()
    messages = 5
    for i in range(messages):
        out = alice.encrypt_message(f"A{i}".encode(), AD)
        assert bob.decrypt_message(out, AD) == f"A{i}".encode()
        back = bob.encrypt_message(f"B{i}".encode(), AD)
        assert alice.decrypt_message(back, AD) == f"B{i}".encode()


def test_batches_before_and_after_ratchet_turns():
    alice, bob = _pair()
    batch_a = [alice.encrypt_message(str(i).encode(), AD) for i in range(4)]
    for i, wire in enumerate(batch_a):
        assert bob.decrypt_message(wire, AD) == str(i).encode()

    bob_reply = bob.encrypt_message(b"x", AD)
    assert alice.decrypt_message(bob_reply, AD) == b"x"

    batch_a2 = [alice.encrypt_message(str(i).encode(), AD) for i in range(4)]
    for i, wire in enumerate(batch_a2):
        assert bob.decrypt_message(wire, AD) == str(i).encode()


def test_out_of_order_messages_decrypt_via_skip_buffer():
    alice, bob = _pair()
    out = alice.encrypt_message(b"init", AD)
    bob.decrypt_message(out, AD)
    back_0 = bob.encrypt_message(b"m0", AD)
    back_1 = bob.encrypt_message(b"m1", AD)
    back_2 = bob.encrypt_message(b"m2", AD)
    back_3 = bob.encrypt_message(b"m3", AD)

    assert alice.decrypt_message(back_2, AD) == b"m2"
    assert alice.decrypt_message(back_1, AD) == b"m1"
    assert alice.decrypt_message(back_0, AD) == b"m0"
    assert alice.decrypt_message(back_3, AD) == b"m3"


def test_replayed_message_is_rejected():
    alice, bob = _pair()
    wire = alice.encrypt_message(b"once", AD)
    assert bob.decrypt_message(wire, AD) == b"once"
    with pytest.raises(DecryptionError):
        bob.decrypt_message(wire, AD)


def test_tampered_ciphertext_is_rejected():
    alice, bob = _pair()
    wire = alice.encrypt_message(b"message", AD)
    flipped = wire[:-1] + bytes([wire[-1] ^ 0xFF])
    with pytest.raises(DecryptionError, match="authenticat"):
        bob.decrypt_message(flipped, AD)


def test_tampered_header_is_rejected():
    alice, bob = _pair()
    wire = alice.encrypt_message(b"message", AD)
    header = unpack_header(wire[:_HEADER_SIZE])
    forged_header = bytes([header.dh[0] ^ 0x01]) + header.dh[1:]
    forged = pack_header(type("H", (), {"dh": forged_header, "pn": header.pn, "n": header.n})())
    wire_forged = forged + wire[_HEADER_SIZE:]
    with pytest.raises(DecryptionError):
        bob.decrypt_message(wire_forged, AD)


def test_wrong_associated_data_fails():
    alice, bob = _pair()
    wire = alice.encrypt_message(b"secret", AD)
    with pytest.raises(DecryptionError):
        bob.decrypt_message(wire, b"other-ad")


def test_export_import_preserves_conversation_state():
    alice, bob = _pair()

    out1 = alice.encrypt_message(b"first", AD)
    assert bob.decrypt_message(out1, AD) == b"first"

    out2 = alice.encrypt_message(b"second", AD)
    alice_exported = alice.export_state()
    bob_exported = bob.export_state()

    alice2 = DoubleRatchet.from_state_bytes(alice_exported)
    bob2 = DoubleRatchet.from_state_bytes(bob_exported)

    assert bob2.decrypt_message(out2, AD) == b"second"
    reply = bob2.encrypt_message(b"back", AD)
    assert alice2.decrypt_message(reply, AD) == b"back"

    # Original instances remain independently usable.
    after = bob.encrypt_message(b"still-live", AD)
    assert alice.decrypt_message(after, AD) == b"still-live"


def test_export_import_preserves_skipped_keys():
    alice, bob = _pair()
    out = alice.encrypt_message(b"init", AD)
    assert bob.decrypt_message(out, AD) == b"init"
    replies = [bob.encrypt_message(str(i).encode(), AD) for i in range(4)]

    # Alice receives one message out of order: indexes 0/1 enter the skip
    # buffer while index 2 decrypts inline.
    assert alice.decrypt_message(replies[2], AD) == b"2"

    alice2 = DoubleRatchet.from_state_bytes(alice.export_state())
    bob2 = DoubleRatchet.from_state_bytes(bob.export_state())

    assert alice2.decrypt_message(replies[0], AD) == b"0"
    assert alice2.decrypt_message(replies[1], AD) == b"1"
    assert alice2.decrypt_message(replies[3], AD) == b"3"

    after_export = bob2.encrypt_message(b"post-restore", AD)
    assert alice2.decrypt_message(after_export, AD) == b"post-restore"


@pytest.mark.parametrize("bad", [b"", b"\x00" * 3, b"\x00" * (_HEADER_SIZE + 15)])
def test_malformed_messages_are_rejected(bad):
    alice, bob = _pair()
    with pytest.raises(RatchetError):
        bob.decrypt_message(bad, AD)


def test_unsupported_header_version_rejected_after_length():
    alice, bob = _pair()
    wire = alice.encrypt_message(b"x", AD)
    bad = bytes([0x63]) + wire[1:]
    with pytest.raises(RatchetError, match="version"):
        bob.decrypt_message(bad, AD)


def test_unpack_header_rejects_wrong_length():
    with pytest.raises(RatchetError, match="header"):
        unpack_header(b"\x00" * (_HEADER_SIZE - 1))
    valid = unpack_header(
        b"\x01" + bytes(32) + (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
    )
    assert valid.n == 0


def test_derive_message_key_rejects_negative_index():
    with pytest.raises(ValueError):
        derive_message_key(bytes(32), -1)


def test_decrypt_without_receiving_chain_raises():
    alice, bob = _pair()
    # Alice's initial state has no receiving chain: a message on the *same*
    # DH turn (initiator's known remote key) cannot decrypt.
    wire = pack_message(Header(alice._remote_dh, 0, 0), b"X" * 16)
    with pytest.raises(DecryptionError, match="receiving chain"):
        alice.decrypt_message(wire, AD)


def test_decrypt_index_too_far_ahead_raises():
    alice, bob = _pair()
    out = alice.encrypt_message(b"init", AD)
    assert bob.decrypt_message(out, AD) == b"init"
    reply = bob.encrypt_message(b"reply", AD)
    assert alice.decrypt_message(reply, AD) == b"reply"

    # Same DH turn, but n beyond the maximum skip window.
    too_far = alice._nr + 1000 + 1
    wire = pack_message(
        Header(x25519_public_raw(bob._local_dh), 0, too_far), b"X" * 16
    )
    with pytest.raises(DecryptionError, match="far ahead"):
        alice.decrypt_message(wire, AD)


def test_skip_bound_exceeded_on_ratchet_raises():
    alice, bob = _pair()
    out = alice.encrypt_message(b"init", AD)
    assert bob.decrypt_message(out, AD) == b"init"
    reply = bob.encrypt_message(b"reply", AD)
    assert alice.decrypt_message(reply, AD) == b"reply"

    fresh = x25519_public_raw(X25519PrivateKey.generate())
    wire = pack_message(Header(fresh, 5_000_000, 0), b"X" * 16)
    with pytest.raises(DecryptionError, match="skip bound"):
        alice.decrypt_message(wire, AD)


def test_preratched_messages_enter_skip_buffer():
    alice, bob = _pair()
    # Bob's first send jumps straight to a fresh ratchet key; Alice must
    # pre-skip the send-side chain keys so his older indexes stay decryptable.
    out = alice.encrypt_message(b"init", AD)
    assert bob.decrypt_message(out, AD) == b"init"
    reply = bob.encrypt_message(b"reply", AD)
    assert alice.decrypt_message(reply, AD) == b"reply"

    turn_key = X25519PrivateKey.generate()
    new_dh = x25519_public_raw(turn_key)
    # Alice will receive a message whose dh is new_dh with pn=3 (three keys
    # skipped into the buffer before index 0 decrypts).
    wire = pack_message(Header(new_dh, 3, 0), b"X" * 16)
    with pytest.raises(DecryptionError, match="auth"):
        alice.decrypt_message(wire, AD)
    assert len(alice._skipped) >= 2


def test_skip_buffer_exhausted_raises():
    seed_key = b"\x5e" * 32
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    dh_ab = dh(alice_priv, x25519_public_raw(bob_priv))
    rk, start = root_chain(seed_key, dh_ab)
    alice = DoubleRatchet(
        rk, start, alice_priv, x25519_public_raw(bob_priv), initiator=True, max_skip=1
    )
    bob = DoubleRatchet(
        rk, start, bob_priv, x25519_public_raw(alice_priv), initiator=False, max_skip=1
    )
    out = alice.encrypt_message(b"init", AD)
    assert bob.decrypt_message(out, AD) == b"init"
    reply = bob.encrypt_message(b"reply", AD)
    assert alice.decrypt_message(reply, AD) == b"reply"

    # Fill the single skipped-key slot, then pre-skip invites one more entry.
    alice._nr = 5
    alice._skipped[(alice._remote_dh, 6)] = bytes(32)
    fresh = x25519_public_raw(X25519PrivateKey.generate())
    wire = pack_message(Header(fresh, 6, 0), b"X" * 16)
    with pytest.raises(DecryptionError, match="exhausted"):
        alice.decrypt_message(wire, AD)


def test_send_requires_remote_key():
    seed_key = b"\x5e" * 32
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    rk, start = root_chain(seed_key, dh(alice_priv, x25519_public_raw(bob_priv)))
    orphan = DoubleRatchet(rk, start, alice_priv, None, initiator=False)
    with pytest.raises(RatchetError, match="remote"):
        orphan.encrypt_message(b"x", AD)


def test_from_state_rejects_malformed_input():
    seed_key = b"\x5e" * 32
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    rk, start = root_chain(seed_key, dh(alice_priv, x25519_public_raw(bob_priv)))
    valid = DoubleRatchet(
        rk, start, alice_priv, x25519_public_raw(bob_priv), initiator=True
    )
    out = valid.encrypt_message(b"x", AD)
    bob = DoubleRatchet(
        rk, start, bob_priv, x25519_public_raw(alice_priv), initiator=False
    )
    bob.decrypt_message(out, AD)
    blob = bob.export_state()

    too_short = blob[: _STATE_HEADER.size - 1]
    with pytest.raises(RatchetError, match="malformed ratchet state"):
        DoubleRatchet.from_state_bytes(too_short)

    bad_version = bytes([0]) + blob[1:]
    with pytest.raises(RatchetError, match="state version"):
        DoubleRatchet.from_state_bytes(bad_version)

    short_body = blob[: _STATE_HEADER.size + 66]
    with pytest.raises(RatchetError, match="state body"):
        DoubleRatchet.from_state_bytes(short_body)

    before_skip = blob[:_STATE_HEADER.size + 68]
    wrong_len = before_skip + (999).to_bytes(4, "big")
    with pytest.raises(RatchetError, match="skipped-key buffer"):
        DoubleRatchet.from_state_bytes(wrong_len)

    odd = blob[:_STATE_HEADER.size + 64] + (3).to_bytes(4, "big") + b"abc"
    with pytest.raises(RatchetError, match="truncated"):
        DoubleRatchet.from_state_bytes(odd)

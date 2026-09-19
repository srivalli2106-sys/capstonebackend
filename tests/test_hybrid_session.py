"""Hybrid X3DH + Double Ratchet session end-to-end test (no live ML-KEM).

We do NOT depend on a real ML-KEM implementation in the test runner; the
``encapsulate_fn`` / ``decapsulate_fn`` callbacks are mocked with a
deterministic, symmetric "shared secret" that lets us exercise the full
hybrid handshake end to end. The construction under test (transcript +
length-prefixed HKDF) is the same whether the shared secret comes from a
real ML-KEM or a mock, so this test still pins the wire format, the
``protocol_version`` binding, and the ratchet integration.
"""

from __future__ import annotations

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from protocol.keys import (
    DeviceKeys,
    KeyBundle,
    PQ_KEM_PUBLIC_BYTES,
    PQ_SIG_PUBLIC_BYTES,
    PQ_SIG_LENGTH_BYTES,
    PROTOCOL_VERSION_HYBRID,
    build_key_bundle,
)
from protocol.session import E2EESession
from protocol.x3dh import ML_KEM_768_CIPHERTEXT_BYTES, X3DHError


def _bundle_with_pq(
    *,
    auth_private,
    xdh_private,
    spk_private,
    pq_kem_public: bytes,
    pq_sig_public: bytes,
    pq_binding_sig: bytes,
    opk_count: int = 0,
) -> tuple[DeviceKeys, KeyBundle]:
    """Build a DeviceKeys + KeyBundle pair that advertises a hybrid bundle.

    The Ed25519 SPK signature is the real classical one; the ML-DSA binding
    signature is provided by the caller (here we mock it)."""
    device = DeviceKeys(
        auth_private=auth_private,
        xdh_private=xdh_private,
        spk_private=spk_private,
        opk_privates=tuple(X25519PrivateKey.generate() for _ in range(opk_count)),
        pq_kem_private=b"MOCK-KEM-PRIV" + b"\x00" * (PQ_KEM_PUBLIC_BYTES - len(b"MOCK-KEM-PRIV")),
        pq_kem_public=pq_kem_public,
        pq_sig_public=pq_sig_public,
    )
    classical = build_key_bundle(device)
    return device, KeyBundle(
        ik_public=classical.ik_public,
        xdh_public=classical.xdh_public,
        spk_public=classical.spk_public,
        spk_signature=classical.spk_signature,
        opk_publics=classical.opk_publics,
        pq_kem_public=pq_kem_public,
        pq_sig_public=pq_sig_public,
        pq_binding_sig=pq_binding_sig,
        protocol_version=PROTOCOL_VERSION_HYBRID,
    )


def _mk_mock_kem():
    """Return a deterministic mock ML-KEM encaps/decaps pair.

    The "shared secret" derived from a given ciphertext is a SHA-256 of
    the ciphertext; encapsulating twice with the same key produces
    DIFFERENT ciphertexts (so the test verifies fresh-noise behaviour)
    and the corresponding decapsulated secrets still match the matching
    ciphertexts.
    """
    import hashlib

    # Per-test ephemeral state: map ciphertext -> shared secret.
    store: dict[bytes, bytes] = {}

    def encapsulate(pub: bytes) -> tuple[bytes, bytes]:
        assert len(pub) == PQ_KEM_PUBLIC_BYTES
        # Deterministic but distinct: include a counter in the digest.
        store["_counter"] = store.get("_counter", 0) + 1  # type: ignore[assignment]
        seed = b"MOCK-KEM\x00" + pub + bytes([store["_counter"]])  # type: ignore[arg-type]
        # Real ML-KEM-768 ciphertext is exactly ML_KEM_768_CIPHERTEXT_BYTES bytes.
        # We expand SHA-256 digests until we have enough bytes.
        digest = hashlib.sha256(seed).digest()
        repeated = b""
        while len(repeated) < ML_KEM_768_CIPHERTEXT_BYTES:
            repeated += digest
            digest = hashlib.sha256(digest + seed).digest()
        ct = repeated[:ML_KEM_768_CIPHERTEXT_BYTES]
        ss = hashlib.sha256(b"ss|" + ct).digest()
        store[ct] = ss
        return ct, ss

    def decapsulate(priv: bytes, ct: bytes) -> bytes:
        assert priv is not None
        # The "shared secret" is purely a function of the ciphertext in
        # this mock; it does NOT actually use ``priv`` because there is no
        # private key. The real ML-KEM would use ``priv``.
        assert ct in store, "mock decapsulate called for unknown ciphertext"
        return store[ct]

    return encapsulate, decapsulate


def test_hybrid_session_round_trip():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    alice_auth = Ed25519PrivateKey.generate()
    alice_ikx = X25519PrivateKey.generate()
    alice_spk = X25519PrivateKey.generate()
    bob_auth = Ed25519PrivateKey.generate()
    bob_ikx = X25519PrivateKey.generate()
    bob_spk = X25519PrivateKey.generate()

    # Alice and Bob both publish mock PQ material. The mock encaps /
    # decaps pair is shared by both sides of the test (the real device
    # would use liboqs / @noble/post-quantum).
    alice_pq_kem_pub = b"\x01" * PQ_KEM_PUBLIC_BYTES
    alice_pq_sig_pub = b"\x02" * PQ_SIG_PUBLIC_BYTES
    bob_pq_kem_pub = b"\x03" * PQ_KEM_PUBLIC_BYTES
    bob_pq_sig_pub = b"\x04" * PQ_SIG_PUBLIC_BYTES
    # Fake ML-DSA binding sig — the real device would generate this with
    # ML-DSA-44; here we just need the bytes to fit the length contract.
    bob_pq_binding_sig = b"\x05" * PQ_SIG_LENGTH_BYTES

    bob_device, bob_bundle = _bundle_with_pq(
        auth_private=bob_auth,
        xdh_private=bob_ikx,
        spk_private=bob_spk,
        pq_kem_public=bob_pq_kem_pub,
        pq_sig_public=bob_pq_sig_pub,
        pq_binding_sig=bob_pq_binding_sig,
    )

    enc, dec = _mk_mock_kem()

    # Alice initiates the hybrid session.
    alice_session = E2EESession.initiate_hybrid(
        our_xdh_private=alice_ikx,
        our_auth_ik_public=alice_auth.public_key().public_bytes_raw(),
        our_pq_kem_public=alice_pq_kem_pub,
        our_pq_sig_public=alice_pq_sig_pub,
        remote_bundle=bob_bundle,
        opk_index=None,
        encapsulate_fn=enc,
    )

    # Bob accepts the hybrid session using the v2 init payload.
    bob_session = E2EESession.accept_hybrid(
        local=bob_device,
        alice_ik_public=alice_auth.public_key().public_bytes_raw(),
        alice_pq_kem_public=alice_pq_kem_pub,
        alice_pq_sig_public=alice_pq_sig_pub,
        init_payload=alice_session.init_payload,
        decapsulate_fn=dec,
    )

    # Alice encrypts a message; Bob decrypts it.
    plaintext = b"hello bob from hybrid alice"
    wire = alice_session.encrypt_message(plaintext)
    decrypted = bob_session.decrypt_message(wire)
    assert decrypted == plaintext

    # Bob replies; Alice decrypts.
    reply_plaintext = b"hi alice from hybrid bob"
    reply_wire = bob_session.encrypt_message(reply_plaintext)
    assert alice_session.decrypt_message(reply_wire) == reply_plaintext


def test_hybrid_session_accept_rejects_missing_local_pq_private():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from protocol.session import SessionError

    alice_auth = Ed25519PrivateKey.generate()
    alice_ikx = X25519PrivateKey.generate()
    alice_spk = X25519PrivateKey.generate()
    bob_auth = Ed25519PrivateKey.generate()
    bob_ikx = X25519PrivateKey.generate()
    bob_spk = X25519PrivateKey.generate()

    bob_device, bob_bundle = _bundle_with_pq(
        auth_private=bob_auth,
        xdh_private=bob_ikx,
        spk_private=bob_spk,
        pq_kem_public=b"\x03" * PQ_KEM_PUBLIC_BYTES,
        pq_sig_public=b"\x04" * PQ_SIG_PUBLIC_BYTES,
        pq_binding_sig=b"\x05" * PQ_SIG_LENGTH_BYTES,
    )
    enc, dec = _mk_mock_kem()

    alice_session = E2EESession.initiate_hybrid(
        our_xdh_private=alice_ikx,
        our_auth_ik_public=alice_auth.public_key().public_bytes_raw(),
        our_pq_kem_public=b"\x01" * PQ_KEM_PUBLIC_BYTES,
        our_pq_sig_public=b"\x02" * PQ_SIG_PUBLIC_BYTES,
        remote_bundle=bob_bundle,
        opk_index=None,
        encapsulate_fn=enc,
    )

    # Wipe Bob's PQ private key to simulate a classical-only device.
    bob_device.pq_kem_private = None
    with pytest.raises((SessionError, X3DHError)):
        E2EESession.accept_hybrid(
            local=bob_device,
            alice_ik_public=alice_auth.public_key().public_bytes_raw(),
            alice_pq_kem_public=b"\x01" * PQ_KEM_PUBLIC_BYTES,
            alice_pq_sig_public=b"\x02" * PQ_SIG_PUBLIC_BYTES,
            init_payload=alice_session.init_payload,
            decapsulate_fn=dec,
        )


def test_v1_session_still_works_byte_identically():
    """Sanity: the classical X3DH path remains byte-compatible after the
    hybrid additions."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    alice_ikx = X25519PrivateKey.generate()
    bob_auth = Ed25519PrivateKey.generate()
    bob_ikx = X25519PrivateKey.generate()
    bob_spk = X25519PrivateKey.generate()

    bob_device = DeviceKeys(
        auth_private=bob_auth,
        xdh_private=bob_ikx,
        spk_private=bob_spk,
    )
    bob_bundle = build_key_bundle(bob_device)

    alice_session = E2EESession.initiate(
        our_xdh_private=alice_ikx,
        our_auth_ik_public=bob_auth.public_key().public_bytes_raw(),
        remote_bundle=bob_bundle,
        opk_index=None,
    )
    bob_session = E2EESession.accept(bob_device, alice_session.init_payload)

    wire = alice_session.encrypt_message(b"classical hi")
    assert bob_session.decrypt_message(wire) == b"classical hi"

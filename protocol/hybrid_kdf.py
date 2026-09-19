"""hybrid_kdf.py — domain-separated hybrid KDF (classical X3DH + ML-KEM-768).

This module combines the classical X3DH shared secret and the ML-KEM-768
shared secret into a single 32-byte hybrid root secret using HKDF-SHA256.

The construction is intentionally explicit and domain-separated so that the
classical and post-quantum components cannot be confused, swapped, or
re-used in another context:

    transcript = SHA-256(
        "secure-messaging-hybrid-kem-handshake-v1"
        || version_tag
        || alice_ik_pub
        || alice_ikx_pub
        || bob_ik_pub
        || bob_ikx_pub
        || bob_spk_pub
        || bob_pq_kem_public
        || bob_pq_sig_public,
    )

    ikm = transcript
          || LP(Z_classical) || Z_classical
          || LP(Z_pq)       || Z_pq

    root_secret = HKDF-SHA256(
        ikm,
        info = b"secure-messaging-hybrid-root-v1",
        length = 32,
    )

Where ``LP(x)`` is the 2-byte big-endian length of ``x`` (so the two
shared secrets are concatenated with unambiguous framing — the KDF input
is never the result of an ambiguous concatenation). ``version_tag`` is
the single-byte integer 1 or 2 so a v1 transcript can never collide with
a v2 transcript.

This module is the single source of truth for the construction; the
frontend mirrors it in TypeScript (`src/crypto/hybridKdf.ts`) and the
two implementations share deterministic test vectors in
``tests/test_hybrid_kdf.py`` / ``test/hybridKdf.test.ts``.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Public constants — re-exported and reused by the frontend so the two
# implementations can never drift without breaking a test.
TRANSCRIPT_CONTEXT = b"secure-messaging-hybrid-kem-handshake-v1"
ROOT_INFO = b"secure-messaging-hybrid-root-v1"
LP_STRUCT = struct.Struct(">H")  # 2-byte big-endian length prefix

# Protocol version (1 = classical, 2 = hybrid). Bound into the transcript.
PROTOCOL_VERSION_CLASSICAL = 1
PROTOCOL_VERSION_HYBRID = 2


def hybrid_transcript(
    *,
    protocol_version: int,
    alice_ik_pub: bytes,
    alice_ikx_pub: bytes,
    bob_ik_pub: bytes,
    bob_ikx_pub: bytes,
    bob_spk_pub: bytes,
    bob_pq_kem_public: bytes,
    bob_pq_sig_public: bytes,
) -> bytes:
    """Compute the 32-byte SHA-256 transcript for the hybrid handshake.

    All inputs are raw byte material; no length prefixes inside the
    transcript itself — the caller is responsible for supplying the exact
    byte strings that were signed / agreed during the handshake.

    Note: ``alice_pq_kem_public`` and ``alice_pq_sig_public`` are NOT
    included here. They are already bound to alice's identity by the
    ML-DSA ``pq_binding_sig`` on the bundle, which is verified by the
    peer before this transcript is ever computed.
    """
    if protocol_version not in (PROTOCOL_VERSION_CLASSICAL, PROTOCOL_VERSION_HYBRID):
        raise ValueError(
            f"protocol_version must be {PROTOCOL_VERSION_CLASSICAL} or "
            f"{PROTOCOL_VERSION_HYBRID}, got {protocol_version}"
        )
    h = hashlib.sha256()
    h.update(TRANSCRIPT_CONTEXT)
    h.update(bytes([protocol_version]))
    h.update(alice_ik_pub)
    h.update(alice_ikx_pub)
    h.update(bob_ik_pub)
    h.update(bob_ikx_pub)
    h.update(bob_spk_pub)
    h.update(bob_pq_kem_public)
    h.update(bob_pq_sig_public)
    return h.digest()


def hybrid_root_secret(
    *,
    protocol_version: int,
    alice_ik_pub: bytes,
    alice_ikx_pub: bytes,
    bob_ik_pub: bytes,
    bob_ikx_pub: bytes,
    bob_spk_pub: bytes,
    bob_pq_kem_public: bytes,
    bob_pq_sig_public: bytes,
    z_classical: bytes,
    z_pq: bytes,
) -> bytes:
    """Compute the 32-byte hybrid root secret.

    Both sides of the handshake call this with the same transcript inputs
    and the same Z_classical / Z_pq values. The result is the initial root
    key handed to the Double Ratchet — exactly as the classical X3DH
    shared secret is today — so the ratchet itself remains unchanged.
    """
    transcript = hybrid_transcript(
        protocol_version=protocol_version,
        alice_ik_pub=alice_ik_pub,
        alice_ikx_pub=alice_ikx_pub,
        bob_ik_pub=bob_ik_pub,
        bob_ikx_pub=bob_ikx_pub,
        bob_spk_pub=bob_spk_pub,
        bob_pq_kem_public=bob_pq_kem_public,
        bob_pq_sig_public=bob_pq_sig_public,
    )
    ikm = (
        transcript
        + LP_STRUCT.pack(len(z_classical))
        + z_classical
        + LP_STRUCT.pack(len(z_pq))
        + z_pq
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=ROOT_INFO,
    ).derive(ikm)

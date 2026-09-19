"""x3dh.py — X3DH key agreement around the backend's key bundles.

Two wire versions are supported:

* v1 (classical only)::

      INIT = >B 32s 32s B
           = version(1) | ik_x_public_A(32) | ek_public_A(32) | opk_index(1; 0xFF = none)

  Shared secret::

      SK = HKDF( DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B)
               || DH(EK_A, OPK_B) )

* v2 (hybrid: classical X3DH + ML-KEM-768)::

      INIT = >B 32s 1088s 1184s 32s B
           = version(2) | ik_x_public_A(32) | kem_ciphertext(1088)
                       | alice_pq_kem_pub(1184) | ek_public_A(32)
                       | opk_index(1; 0xFF = none)

  Shared secret (composed by ``protocol.hybrid_kdf``)::

      Z_classical = X3DH shared secret (same DH terms as v1)
      Z_pq        = ML-KEM-768 decapsulate(kem_ciphertext, local pq_kem_priv)
      transcript  = SHA256(secure-messaging-hybrid-kem-handshake-v1
                            || version_tag
                            || alice_ik_pub || alice_ikx_pub
                            || bob_ik_pub   || bob_ikx_pub
                            || bob_spk_pub
                            || bob_pq_kem_pub || bob_pq_sig_pub)
      ikm         = transcript || LP(Z_classical) || Z_classical
                                  || LP(Z_pq)       || Z_pq
      root_secret = HKDF-SHA256(ikm, info=secure-messaging-hybrid-root-v1, 32)

  ``LP(x)`` is the 2-byte big-endian length prefix so the two shared
  secrets are framed unambiguously inside the KDF input.

Both sides end up with the same ``root_secret``, which is then handed to
the existing Double Ratchet exactly as the v1 ``shared_secret`` is today.

The init payload is the only thing that ever crosses the wire; the rest
is computed locally on each device. The backend never runs either X3DH
or ML-KEM. It only stores key material and forwards opaque init bytes.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .keys import (
    DeviceKeys,
    KeyBundle,
    dh,
    verify_signed_prekey,
    x25519_public_raw,
)

X3DH_INFO = b"secure-messaging-x3dh-v1"
INIT_VERSION_V1 = 1
INIT_VERSION_V2 = 2
NO_OPK = 0xFF

# v1: version(1) | ik_x_public(32) | ek_public(32) | opk_index(1)
_INIT_STRUCT_V1 = struct.Struct(">B 32s 32s B")
# v2: version(1) | ik_x_public(32) | kem_ct(1088) | alice_pq_kem_pub(1184)
#      | ek_public(32) | opk_index(1)
_INIT_STRUCT_V2 = struct.Struct(">B 32s 1088s 1184s 32s B")

# ML-KEM-768 (NIST FIPS 203) sizes
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_PUBLIC_KEY_BYTES = 1184


class X3DHError(ValueError):
    """Raised when X3DH material is malformed or cannot be agreed."""


def _shared_secret(parts: list[bytes]) -> bytes:
    material = b"".join(parts)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=X3DH_INFO,
    ).derive(material)


def _initiator_dh(
    ephemeral: X25519PrivateKey,
    our_xdh: X25519PrivateKey,
    remote: KeyBundle,
    opk_public: bytes | None,
) -> list[bytes]:
    # RFC-ordered terms: DH1=IK_A/SPK_B, DH2=EK_A/IK_B, DH3=EK_A/SPK_B,
    # DH4=EK_A/OPK_B.
    return [
        dh(our_xdh, remote.spk_public),
        dh(ephemeral, remote.xdh_public),
        dh(ephemeral, remote.spk_public),
    ] + ([dh(ephemeral, opk_public)] if opk_public is not None else [])


# ---------------------------------------------------------------------------
# v1 wire format (byte-compatible with the previous protocol)
# ---------------------------------------------------------------------------


def pack_init_message_v1(
    ik_x_public: bytes,
    ek_public: bytes,
    opk_index: int | None,
) -> bytes:
    return _INIT_STRUCT_V1.pack(
        INIT_VERSION_V1,
        ik_x_public,
        ek_public,
        NO_OPK if opk_index is None else opk_index,
    )


def unpack_init_message_v1(payload: bytes) -> dict[str, object]:
    if len(payload) != _INIT_STRUCT_V1.size:
        raise X3DHError("malformed X3DH v1 init message")
    version, ik_x_public, ek_public, opk_index = _INIT_STRUCT_V1.unpack(payload)
    if version != INIT_VERSION_V1:
        raise X3DHError(f"unsupported X3DH v1 version {version}")
    opk_index = None if opk_index == NO_OPK else opk_index
    return {
        "version": version,
        "ik_x_public": ik_x_public,
        "ek_public": ek_public,
        "opk_index": opk_index,
    }


# Backwards-compat aliases: the original protocol code called these
# ``pack_init_message`` / ``unpack_init_message`` and tests still import
# them under the original names.
def pack_init_message(
    ik_x_public: bytes,
    ek_public: bytes,
    opk_index: int | None,
) -> bytes:
    """Deprecated alias for ``pack_init_message_v1`` (kept for backwards
    compatibility with existing tests and callers)."""
    return pack_init_message_v1(ik_x_public, ek_public, opk_index)


def unpack_init_message(payload: bytes) -> dict[str, object]:
    """Deprecated alias: dispatches on the leading version byte to v1/v2."""
    if len(payload) < 1:
        raise X3DHError("malformed X3DH init message")
    version = payload[0]
    if version == INIT_VERSION_V1:
        return unpack_init_message_v1(payload)
    if version == INIT_VERSION_V2:
        return unpack_init_message_v2(payload)
    raise X3DHError(f"unsupported X3DH init version {version}")


# ---------------------------------------------------------------------------
# v2 wire format (hybrid)
# ---------------------------------------------------------------------------


def pack_init_message_v2(
    ik_x_public: bytes,
    kem_ciphertext: bytes,
    alice_pq_kem_public: bytes,
    ek_public: bytes,
    opk_index: int | None,
) -> bytes:
    if len(kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
        raise X3DHError(
            f"kem_ciphertext must be {ML_KEM_768_CIPHERTEXT_BYTES} bytes, "
            f"got {len(kem_ciphertext)}"
        )
    if len(alice_pq_kem_public) != ML_KEM_768_PUBLIC_KEY_BYTES:
        raise X3DHError(
            f"alice_pq_kem_public must be {ML_KEM_768_PUBLIC_KEY_BYTES} "
            f"bytes, got {len(alice_pq_kem_public)}"
        )
    return _INIT_STRUCT_V2.pack(
        INIT_VERSION_V2,
        ik_x_public,
        kem_ciphertext,
        alice_pq_kem_public,
        ek_public,
        NO_OPK if opk_index is None else opk_index,
    )


def unpack_init_message_v2(payload: bytes) -> dict[str, object]:
    if len(payload) != _INIT_STRUCT_V2.size:
        raise X3DHError(
            f"malformed X3DH v2 init message: expected "
            f"{_INIT_STRUCT_V2.size} bytes, got {len(payload)}"
        )
    (
        version,
        ik_x_public,
        kem_ciphertext,
        alice_pq_kem_public,
        ek_public,
        opk_index,
    ) = _INIT_STRUCT_V2.unpack(payload)
    if version != INIT_VERSION_V2:
        raise X3DHError(f"unsupported X3DH v2 version {version}")
    opk_index = None if opk_index == NO_OPK else opk_index
    return {
        "version": version,
        "ik_x_public": ik_x_public,
        "kem_ciphertext": kem_ciphertext,
        "alice_pq_kem_public": alice_pq_kem_public,
        "ek_public": ek_public,
        "opk_index": opk_index,
    }


def associated_data(ik_x_public_a: bytes, ik_x_public_b: bytes) -> bytes:
    return ik_x_public_a + ik_x_public_b


# ---------------------------------------------------------------------------
# Classical X3DH (v1): same as before, byte-compatible.
# ---------------------------------------------------------------------------


class Initiation:
    """Result of an initiator-side X3DH (v1 classical)."""

    def __init__(
        self,
        shared_secret: bytes,
        ad: bytes,
        init_payload: bytes,
        opk_index: int | None,
        ek_private: X25519PrivateKey,
    ) -> None:
        self.shared_secret = shared_secret
        self.ad = ad
        self.init_payload = init_payload
        self.opk_index = opk_index
        # The initiator's ephemeral must be reused as the ratchet's initial
        # key so both sides agree on the first DH output.
        self.ek_private = ek_private


def x3dh_initiate(
    our_xdh_private: X25519PrivateKey,
    auth_ik_public: bytes,
    remote_bundle: KeyBundle,
    opk_index: int | None,
) -> Initiation:
    """Initiator step (v1 classical): verify SPK, agree SK, build the init frame."""
    if opk_index is not None:
        if not (0 <= opk_index < len(remote_bundle.opk_publics)):
            raise X3DHError("requested one-time prekey index unavailable")
    if not verify_signed_prekey(
        remote_bundle.ik_public,
        remote_bundle.spk_public,
        remote_bundle.spk_signature,
    ):
        raise X3DHError("signed prekey signature verification failed")

    ephemeral = X25519PrivateKey.generate()
    opk_public = (
        remote_bundle.opk_publics[opk_index] if opk_index is not None else None
    )
    dh_parts = _initiator_dh(ephemeral, our_xdh_private, remote_bundle, opk_public)
    sk = _shared_secret(dh_parts)
    ad = associated_data(x25519_public_raw(our_xdh_private), remote_bundle.xdh_public)
    payload = pack_init_message_v1(
        x25519_public_raw(our_xdh_private),
        x25519_public_raw(ephemeral),
        opk_index,
    )
    return Initiation(sk, ad, payload, opk_index, ephemeral)


class Acceptance:
    """Result of a responder-side X3DH (v1 classical)."""

    def __init__(
        self,
        shared_secret: bytes,
        ad: bytes,
        initiator_ik_x_public: bytes,
        initiator_ek_public: bytes,
        consumed_opk_index: int | None,
    ) -> None:
        self.shared_secret = shared_secret
        self.ad = ad
        self.initiator_ik_x_public = initiator_ik_x_public
        self.initiator_ek_public = initiator_ek_public
        self.consumed_opk_index = consumed_opk_index


def x3dh_respond(local: DeviceKeys, init_payload: bytes) -> Acceptance:
    """Responder step (v1 classical): consume the matching OPK and recompute SK."""
    info = unpack_init_message_v1(init_payload)
    opk_index = info["opk_index"]
    if opk_index is not None:
        if not (0 <= opk_index < len(local.opk_privates)):
            raise X3DHError("unavailable one-time prekey index")
        opk_priv = local.opk_privates[opk_index]
    else:
        opk_priv = None

    ek_public = info["ek_public"]
    dh_parts = [
        dh(local.spk_private, info["ik_x_public"]),
        dh(local.xdh_private, ek_public),
        dh(local.spk_private, ek_public),
    ]
    if opk_priv is not None:
        dh_parts.append(dh(opk_priv, ek_public))

    sk = _shared_secret(dh_parts)
    ad = associated_data(info["ik_x_public"], x25519_public_raw(local.xdh_private))
    return Acceptance(
        sk,
        ad,
        info["ik_x_public"],
        ek_public,
        opk_index,
    )


# ---------------------------------------------------------------------------
# Hybrid session (v2): classical X3DH + ML-KEM-768 -> hybrid root secret.
#
# The actual ML-KEM encaps/decaps call is supplied by the caller, because
# the server never runs ML-KEM and the protocol package deliberately stays
# independent of the device's PQ crypto library.
# ---------------------------------------------------------------------------


class HybridAcceptance:
    """Result of a responder-side hybrid X3DH (v2)."""

    def __init__(
        self,
        root_secret: bytes,
        ad: bytes,
        initiator_ik_x_public: bytes,
        initiator_ek_public: bytes,
        consumed_opk_index: int | None,
        kem_ciphertext: bytes,
        alice_pq_kem_public: bytes,
    ) -> None:
        self.root_secret = root_secret
        self.ad = ad
        self.initiator_ik_x_public = initiator_ik_x_public
        self.initiator_ek_public = initiator_ek_public
        self.consumed_opk_index = consumed_opk_index
        self.kem_ciphertext = kem_ciphertext
        self.alice_pq_kem_public = alice_pq_kem_public


def hybrid_x3dh_initiate_v2(
    our_xdh_private: X25519PrivateKey,
    auth_ik_public: bytes,
    our_pq_kem_public: bytes,
    remote_bundle: KeyBundle,
    opk_index: int | None,
    encapsulate_fn,
) -> tuple[Initiation, bytes, bytes]:
    """Initiator step (v2 hybrid).

    ``encapsulate_fn(bob_pq_kem_public)`` must return a tuple
    ``(kem_ciphertext, shared_secret)``. The function is injected so this
    module has no direct dependency on a specific ML-KEM library; the
    device supplies the call (e.g. ``ml_kem768.encapsulate``).

    Returns ``(initiation, kem_ciphertext, z_pq)``. The ``Initiation``
    object carries the classical X3DH ``shared_secret`` and the v2 init
    payload. The two PQ artefacts are returned separately so the caller
    can compose them with the protocol hybrid KDF.
    """
    if remote_bundle.pq_kem_public is None:
        raise X3DHError("peer bundle is missing pq_kem_public; cannot establish hybrid session")
    if not verify_signed_prekey(
        remote_bundle.ik_public,
        remote_bundle.spk_public,
        remote_bundle.spk_signature,
    ):
        raise X3DHError("signed prekey signature verification failed")
    if opk_index is not None:
        if not (0 <= opk_index < len(remote_bundle.opk_publics)):
            raise X3DHError("requested one-time prekey index unavailable")

    ephemeral = X25519PrivateKey.generate()
    opk_public = (
        remote_bundle.opk_publics[opk_index] if opk_index is not None else None
    )
    dh_parts = _initiator_dh(ephemeral, our_xdh_private, remote_bundle, opk_public)
    sk_classical = _shared_secret(dh_parts)
    ad = associated_data(x25519_public_raw(our_xdh_private), remote_bundle.xdh_public)

    # ML-KEM-768 encapsulate against Bob's ML-KEM public key.
    kem_ciphertext, z_pq = encapsulate_fn(remote_bundle.pq_kem_public)

    payload = pack_init_message_v2(
        x25519_public_raw(our_xdh_private),
        kem_ciphertext,
        our_pq_kem_public,
        x25519_public_raw(ephemeral),
        opk_index,
    )
    return (Initiation(sk_classical, ad, payload, opk_index, ephemeral), kem_ciphertext, z_pq)


def hybrid_x3dh_respond_v2(
    *,
    local: DeviceKeys,
    alice_ik_public: bytes,
    alice_pq_kem_public: bytes,
    alice_pq_sig_public: bytes,
    init_payload: bytes,
    decapsulate_fn,
) -> HybridAcceptance:
    """Responder step (v2 hybrid).

    ``alice_ik_public``, ``alice_pq_kem_public``, ``alice_pq_sig_public``
    come from alice's key bundle (fetched separately by the caller, same
    as classical X3DH uses alice's ``ikx_public``). The responder does
    not have to trust them blindly — it MUST verify them, and the ML-DSA
    binding signature on alice's bundle must already have been checked
    before this function is called.

    ``decapsulate_fn(local.pq_kem_private, kem_ciphertext)`` must return
    the shared secret (Z_pq) from ML-KEM-768 decapsulation.

    Returns a ``HybridAcceptance`` carrying the v2 root secret, ready to
    seed the Double Ratchet exactly as the classical X3DH shared secret
    does today.
    """
    if local.pq_kem_private is None:
        raise X3DHError(
            "device is missing pq_kem_private; cannot respond to hybrid session"
        )
    if local.pq_kem_public is None or local.pq_sig_public is None:
        raise X3DHError(
            "device is missing pq_kem_public/pq_sig_public; cannot respond "
            "to hybrid session (transcript needs Bob's own PQ public keys)"
        )

    info = unpack_init_message_v2(init_payload)
    opk_index = info["opk_index"]
    if opk_index is not None:
        if not (0 <= opk_index < len(local.opk_privates)):
            raise X3DHError("unavailable one-time prekey index")
        opk_priv = local.opk_privates[opk_index]
    else:
        opk_priv = None

    ek_public = info["ek_public"]
    dh_parts = [
        dh(local.spk_private, info["ik_x_public"]),
        dh(local.xdh_private, ek_public),
        dh(local.spk_private, ek_public),
    ]
    if opk_priv is not None:
        dh_parts.append(dh(opk_priv, ek_public))

    sk_classical = _shared_secret(dh_parts)
    z_pq = decapsulate_fn(local.pq_kem_private, info["kem_ciphertext"])
    ad = associated_data(info["ik_x_public"], x25519_public_raw(local.xdh_private))

    from .hybrid_kdf import (
        PROTOCOL_VERSION_HYBRID,
        hybrid_root_secret,
    )
    from .keys import ed25519_public_bytes

    bob_ik_pub = ed25519_public_bytes(local.auth_private.public_key())
    bob_ikx_pub = x25519_public_raw(local.xdh_private)
    bob_spk_pub = x25519_public_raw(local.spk_private)

    # Transcript uses BOB's PQ public keys (the responder's), since the
    # initiator already knows them and the responder knows them locally.
    # This mirrors the classical path: ``initiator_ikx_pub`` and
    # ``responder_ikx_pub`` are both bound.
    root_secret = hybrid_root_secret(
        protocol_version=PROTOCOL_VERSION_HYBRID,
        alice_ik_pub=alice_ik_public,
        alice_ikx_pub=info["ik_x_public"],
        bob_ik_pub=bob_ik_pub,
        bob_ikx_pub=bob_ikx_pub,
        bob_spk_pub=bob_spk_pub,
        bob_pq_kem_public=local.pq_kem_public,
        bob_pq_sig_public=local.pq_sig_public,
        z_classical=sk_classical,
        z_pq=z_pq,
    )
    return HybridAcceptance(
        root_secret=root_secret,
        ad=ad,
        initiator_ik_x_public=info["ik_x_public"],
        initiator_ek_public=ek_public,
        consumed_opk_index=opk_index,
        kem_ciphertext=info["kem_ciphertext"],
        alice_pq_kem_public=alice_pq_kem_public,
    )



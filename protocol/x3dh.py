"""x3dh.py — X3DH key agreement around the backend's key bundles.

The initiator (Alice) fetches Bob's bundle from ``/keys/bundle``, verifies the
signed prekey against Bob's registered Ed25519 auth identity, then computes:

    SK = HKDF( DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B)
             || DH(EK_A, OPK_B) )

The responder (Bob) recomputes the same four DH terms from her private keys
and the initiator's carried identity/ephemeral publics. ``AD`` binds the two
X3DH identities so the Double Ratchet's AEAD cannot be redirected to another
peer. The init payload is a small binary frame:

    version(1) | ik_x_public_A(32) | ek_public_A(32) | opk_index(1; 0xFF = none)

One-time prekeys make the agreement deniable-auth, remove-recipient and
zero-knowledge friendly: each fetch from the server hands out a fresh OPK and
consumes it server-side (see :mod:`server.services.key_service`).
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
INIT_VERSION = 1
NO_OPK = 0xFF

_INIT_STRUCT = struct.Struct(">B 32s 32s B")
_AD_MESSAGE_LENGTH = 64


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


def pack_init_message(
    ik_x_public: bytes,
    ek_public: bytes,
    opk_index: int | None,
) -> bytes:
    return _INIT_STRUCT.pack(
        INIT_VERSION,
        ik_x_public,
        ek_public,
        NO_OPK if opk_index is None else opk_index,
    )


def unpack_init_message(payload: bytes) -> dict[str, object]:
    if len(payload) != _INIT_STRUCT.size:
        raise X3DHError("malformed X3DH init message")
    version, ik_x_public, ek_public, opk_index = _INIT_STRUCT.unpack(payload)
    if version != INIT_VERSION:
        raise X3DHError(f"unsupported X3DH version {version}")
    opk_index = None if opk_index == NO_OPK else opk_index
    return {
        "version": version,
        "ik_x_public": ik_x_public,
        "ek_public": ek_public,
        "opk_index": opk_index,
    }


def associated_data(ik_x_public_a: bytes, ik_x_public_b: bytes) -> bytes:
    return ik_x_public_a + ik_x_public_b


class Initiation:
    """Result of an initiator-side X3DH."""

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
    """Initiator step: verify SPK, agree SK, build the init transport frame."""
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
    payload = pack_init_message(
        x25519_public_raw(our_xdh_private),
        x25519_public_raw(ephemeral),
        opk_index,
    )
    return Initiation(sk, ad, payload, opk_index, ephemeral)


class Acceptance:
    """Result of a responder-side X3DH."""

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
    """Responder step: consume the matching OPK and recompute SK."""
    info = unpack_init_message(init_payload)
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

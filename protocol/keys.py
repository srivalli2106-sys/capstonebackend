"""keys.py — device key material for the E2EE protocol.

A device holds several kinds of identity:

  * an Ed25519 *auth identity* — the public half is registered with the
    backend (``ik_public``) and used for proof-of-possession plus signing the
    device's signed prekey;
  * an X25519 *X3DH identity* — participates in the X3DH shared-secret
    computation (identity keys in X3DH must be usable for Diffie-Hellman).

All classical key material is 32 bytes (256-bit), matching the 64-hex-string
contract of :mod:`server.routes.keys`.

This module is intentionally backend-light:

  * The server stores PQ **public** material in the key bundle and relays it.
  * The server does NOT generate ML-KEM or ML-DSA keypairs — that happens on
    the device, where the private keys stay.
  * The server does NOT verify ML-DSA signatures — that also happens on the
    peer's device during the handshake. We document this honestly rather
    than pretending structural length checks equal cryptographic
    verification.

The ML-KEM-768 / ML-DSA-44 size constants live here so both the protocol and
the routes share the same numeric contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# Domain-separator for the SPK signature (unchanged). The Ed25519 signature
# still signs exactly this context + the SPK public key, byte-compatible with
# every previously-registered client.
SPK_SIGN_CONTEXT = b"secure-messaging-signed-prekey-v1"

# Classical key size.
KEY_SIZE = 32

# NIST FIPS 203 / FIPS 204 sizes (used purely for structural validation of
# PQ public material). The actual cryptographic operations happen on the
# device using @noble/post-quantum (frontend) — the backend never runs
# ML-KEM or ML-DSA.
PQ_KEM_PUBLIC_BYTES = 1184  # ML-KEM-768 public key
PQ_SIG_PUBLIC_BYTES = 1312  # ML-DSA-44 public key
PQ_SIG_LENGTH_BYTES = 2420  # ML-DSA-44 signature length

# Protocol version. Integer: 1 = classical, 2 = hybrid (classical + PQ).
# This is the single, normalised representation; the REST routes store and
# serve it as an integer.
PROTOCOL_VERSION_CLASSICAL = 1
PROTOCOL_VERSION_HYBRID = 2


def _priv_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pub_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_from_bytes(raw: bytes) -> Ed25519PublicKey:
    if len(raw) != KEY_SIZE:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def x25519_private_from_bytes(raw: bytes) -> X25519PrivateKey:
    if len(raw) != KEY_SIZE:
        raise ValueError("X25519 private key must be 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def x25519_public_from_bytes(raw: bytes) -> X25519PublicKey:
    if len(raw) != KEY_SIZE:
        raise ValueError("X25519 public key must be 32 bytes")
    return X25519PublicKey.from_public_bytes(raw)


@dataclass
class DeviceKeys:
    """Private key material that stays on the device.

    PQ private material is opaque to the server. The server never reads,
    derives, or transmits it. It lives only inside the encrypted device-keys
    envelope on the local browser. Keeping the fields optional preserves
    backward compatibility for every existing test/classical client that
    builds ``DeviceKeys(auth_private=..., xdh_private=..., spk_private=...)``
    without any PQ arguments.
    """

    auth_private: Ed25519PrivateKey
    xdh_private: X25519PrivateKey
    spk_private: X25519PrivateKey
    opk_privates: tuple = field(default_factory=tuple)
    # PQ private keys — opaque to the server. None for classical clients.
    pq_kem_private: Optional[bytes] = None
    pq_sig_private: Optional[bytes] = None
    # PQ public keys — known to the device (public halves of the privates);
    # needed for the responder side of the hybrid handshake transcript
    # without re-deriving them from the opaque private blobs.
    pq_kem_public: Optional[bytes] = None
    pq_sig_public: Optional[bytes] = None


@dataclass
class KeyBundle:
    """The public material served to peers.

    All PQ fields are optional so the classical-only path is byte-compatible
    with every previously-registered client. A bundle is "hybrid"
    (``protocol_version == 2``) iff all PQ fields are populated; anything
    else is treated as classical.
    """

    ik_public: bytes  # Ed25519 auth identity (32 bytes)
    xdh_public: bytes  # X25519 X3DH identity (32 bytes)
    spk_public: bytes  # X25519 signed prekey (32 bytes)
    spk_signature: bytes  # Ed25519 sig over SPK_SIGN_CONTEXT || spk_public
    opk_publics: tuple = field(default_factory=tuple)
    # Optional PQ public material (None for classical clients).
    pq_kem_public: Optional[bytes] = None  # ML-KEM-768 public (1184 bytes)
    pq_sig_public: Optional[bytes] = None  # ML-DSA-44 public (1312 bytes)
    pq_binding_sig: Optional[bytes] = None  # ML-DSA-44 sig (2420 bytes)
    protocol_version: int = PROTOCOL_VERSION_CLASSICAL

    def public_hex(self) -> dict[str, object]:
        return {
            "ik_public": self.ik_public.hex(),
            "xdh_public": self.xdh_public.hex(),
            "spk_public": self.spk_public.hex(),
            "spk_signature": self.spk_signature.hex(),
            "opk_publics": [key.hex() for key in self.opk_publics],
            "pq_kem_public": self.pq_kem_public.hex() if self.pq_kem_public else None,
            "pq_sig_public": self.pq_sig_public.hex() if self.pq_sig_public else None,
            "pq_binding_sig": self.pq_binding_sig.hex() if self.pq_binding_sig else None,
            "protocol_version": self.protocol_version,
        }


def generate_device_keys(
    *,
    opk_count: int = 0,
    enable_pq: bool = False,
) -> DeviceKeys:
    """Create a fresh device identity.

    ``enable_pq=False`` keeps the existing classical behaviour. When True,
    the caller must provide ``pq_kem_private`` and ``pq_sig_private`` from
    the device's PQ library — this function does NOT generate them, because
    the server must not hold the user's long-term PQ private keys.
    """
    if opk_count < 0:
        raise ValueError("opk_count must be >= 0")
    return DeviceKeys(
        auth_private=Ed25519PrivateKey.generate(),
        xdh_private=X25519PrivateKey.generate(),
        spk_private=X25519PrivateKey.generate(),
        opk_privates=tuple(
            X25519PrivateKey.generate() for _ in range(opk_count)
        ),
    )


def build_key_bundle(device: DeviceKeys) -> KeyBundle:
    """Derive the classical public bundle from a ``DeviceKeys`` instance.

    This function performs NO PQ crypto. It only ever signs the SPK binding
    with the device's Ed25519 auth key. The hybrid binding signature
    (ML-DSA over an extended context) is generated on the **device** before
    the bundle is uploaded; the server stores it as opaque bytes and relays
    it. See ``validate_bundle_structure`` below for what we actually check.
    """
    spk_public = _pub_bytes(device.spk_private.public_key())
    signature = device.auth_private.sign(SPK_SIGN_CONTEXT + spk_public)
    return KeyBundle(
        ik_public=ed25519_public_bytes(device.auth_private.public_key()),
        xdh_public=_pub_bytes(device.xdh_private.public_key()),
        spk_public=spk_public,
        spk_signature=signature,
        opk_publics=tuple(
            _pub_bytes(priv.public_key()) for priv in device.opk_privates
        ),
    )


def verify_signed_prekey(
    ik_public: bytes,
    spk_public: bytes,
    spk_signature: bytes,
) -> bool:
    """Verify the SPK signature against the peer's Ed25519 auth identity."""
    try:
        ed25519_public_from_bytes(ik_public).verify(
            spk_signature, SPK_SIGN_CONTEXT + spk_public
        )
        return True
    except Exception:
        return False


def validate_bundle_structure(bundle: KeyBundle) -> bool:
    """Structural sanity check for a key bundle (server-side, post-upload).

    What this DOES:

    * Verifies the classical Ed25519 SPK signature (using the registered
      Ed25519 auth identity — already what the classical path did).
    * Enforces exact byte lengths for PQ public material when present.
    * Enforces the integer protocol_version is in {1, 2}.

    What this does NOT do:

    * It does NOT cryptographically verify the ML-DSA ``pq_binding_sig``.
      ML-DSA verification requires the device's PQ library; the server
      has none. The initiating peer verifies the ML-DSA binding signature
      on its own during the handshake, using the public material it
      fetched from this very bundle. We explicitly do not claim otherwise.
    """
    if not verify_signed_prekey(bundle.ik_public, bundle.spk_public, bundle.spk_signature):
        return False
    if bundle.protocol_version not in (PROTOCOL_VERSION_CLASSICAL, PROTOCOL_VERSION_HYBRID):
        return False
    if bundle.protocol_version == PROTOCOL_VERSION_HYBRID:
        if (
            bundle.pq_kem_public is None
            or len(bundle.pq_kem_public) != PQ_KEM_PUBLIC_BYTES
        ):
            return False
        if (
            bundle.pq_sig_public is None
            or len(bundle.pq_sig_public) != PQ_SIG_PUBLIC_BYTES
        ):
            return False
        # pq_binding_sig length is structurally checked; cryptographic
        # verification happens on the peer device (see docstring above).
        if (
            bundle.pq_binding_sig is None
            or len(bundle.pq_binding_sig) != PQ_SIG_LENGTH_BYTES
        ):
            return False
    return True


def x25519_public_raw(priv: X25519PrivateKey) -> bytes:
    return _pub_bytes(priv.public_key())


def x25519_private_raw(priv: X25519PrivateKey) -> bytes:
    return _priv_bytes(priv)


def dh(priv: X25519PrivateKey, peer_public: bytes) -> bytes:
    """Raw X25519 shared secret with a peer's 32-byte public key."""
    peer = x25519_public_from_bytes(peer_public)
    return priv.exchange(peer)

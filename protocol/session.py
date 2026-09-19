"""session.py — turn X3DH + Double Ratchet into a usable E2EE session.

A session exists between two devices and is identified, on both ends, by the
pair of X3DH identity publics bound into ``ad``. The initiator creates it from
a fetched peer bundle (optionally with a one-time prekey); the responder builds
it from the received X3DH init payload. Both ends then speak Double Ratchet:

  * ``encrypt(plaintext, extra_ad=b"")`` -> wire bytes for a ``text``/``file``
    envelope ``data`` field.
  * ``decrypt(wire, extra_ad=b"")``  -> plaintext, or raises
    :class:`~protocol.ratchet.DecryptionError` on tampering/replay.
  * ``init_payload`` (initiator) -> wire bytes for the ``session_init``
    envelope ``data`` field.

The session AD is always part of the AEAD input; callers additionally bind
envelope fields (sender/recipient/type) via ``extra_ad`` so ciphertext cannot
be replayed across a different routing context.

State can be persisted with ``export_state()`` / ``from_state_bytes`` so
communication can resume across app restarts without re-running X3DH.

Hybrid (v2) sessions add a post-quantum shared secret from ML-KEM-768 to
the classical X3DH shared secret and combine both via the domain-separated
hybrid KDF in :mod:`protocol.hybrid_kdf`. The result seeds the same
Double Ratchet, so message keys, replay protection, and skipped-message
handling are unchanged.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .hybrid_kdf import (
    PROTOCOL_VERSION_HYBRID,
    hybrid_root_secret,
)
from .kdf import root_chain
from .keys import (
    DeviceKeys,
    KeyBundle,
    ed25519_public_bytes,
    dh,
)
from .ratchet import DoubleRatchet, RatchetError
from .x3dh import (
    x3dh_initiate,
    x3dh_respond,
    hybrid_x3dh_initiate_v2,
    hybrid_x3dh_respond_v2,
    HybridAcceptance,
)

_SESSION_STATE_STRUCT = struct.Struct(">B B B I")

SESSION_STATE_VERSION = 1


class SessionError(RatchetError):
    """Raised on invalid session construction or persistence state."""


class E2EESession:
    """A single direction-agnostic encrypted session between two devices."""

    def __init__(
        self,
        initiator: bool,
        ad: bytes,
        ratchet: DoubleRatchet,
        init_payload: bytes | None = None,
    ) -> None:
        self._initiator = initiator
        self._ad = ad
        self._ratchet = ratchet
        self._init_payload = init_payload

    @property
    def is_initiator(self) -> bool:
        return self._initiator

    @property
    def init_payload(self) -> bytes:
        """The X3DH init frame to send in a ``session_init`` envelope."""
        if self._init_payload is None:
            raise SessionError("only an initiator session carries an init payload")
        return self._init_payload

    @classmethod
    def initiate(
        cls,
        our_xdh_private: X25519PrivateKey,
        our_auth_ik_public: bytes,
        remote_bundle: KeyBundle,
        opk_index: int | None,
    ) -> E2EESession:
        """Build an initiator session against a peer bundle (Alice, v1)."""
        return cls._initiate_v1(
            our_xdh_private, our_auth_ik_public, remote_bundle, opk_index
        )

    @classmethod
    def _initiate_v1(
        cls,
        our_xdh_private: X25519PrivateKey,
        our_auth_ik_public: bytes,
        remote_bundle: KeyBundle,
        opk_index: int | None,
    ) -> E2EESession:
        initiation = x3dh_initiate(
            our_xdh_private, our_auth_ik_public, remote_bundle, opk_index
        )
        root_key, start_chain = root_chain(
            initiation.shared_secret,
            dh(initiation.ek_private, remote_bundle.spk_public),
        )
        ratchet = DoubleRatchet(
            root_key,
            start_chain,
            initiation.ek_private,
            remote_bundle.spk_public,
            initiator=True,
        )
        return cls(True, initiation.ad, ratchet, initiation.init_payload)

    @classmethod
    def initiate_hybrid(
        cls,
        our_xdh_private: X25519PrivateKey,
        our_auth_ik_public: bytes,
        our_pq_kem_public: bytes,
        our_pq_sig_public: bytes,
        remote_bundle: KeyBundle,
        opk_index: int | None,
        encapsulate_fn,
    ) -> E2EESession:
        """Build an initiator session for the hybrid (v2) handshake.

        ``encapsulate_fn(bob_pq_kem_public)`` must return ``(kem_ct, ss_pq)``.
        It is injected so this module does not depend on a specific ML-KEM
        library; the device supplies the call (e.g. ``ml_kem768.encapsulate``).
        """
        if remote_bundle.pq_kem_public is None or remote_bundle.pq_sig_public is None:
            raise SessionError(
                "peer bundle is missing pq_kem_public or pq_sig_public"
            )
        initiation, _kem_ct, _z_pq = hybrid_x3dh_initiate_v2(
            our_xdh_private=our_xdh_private,
            auth_ik_public=our_auth_ik_public,
            our_pq_kem_public=our_pq_kem_public,
            remote_bundle=remote_bundle,
            opk_index=opk_index,
            encapsulate_fn=encapsulate_fn,
        )
        # Compose the hybrid root using the same KDF the responder will use.
        bob_ik_pub = remote_bundle.ik_public
        bob_ikx_pub = remote_bundle.xdh_public
        bob_spk_pub = remote_bundle.spk_public
        root_secret = hybrid_root_secret(
            protocol_version=PROTOCOL_VERSION_HYBRID,
            alice_ik_pub=our_auth_ik_public,
            alice_ikx_pub=x25519_pub_of(our_xdh_private),
            bob_ik_pub=bob_ik_pub,
            bob_ikx_pub=bob_ikx_pub,
            bob_spk_pub=bob_spk_pub,
            bob_pq_kem_public=remote_bundle.pq_kem_public,
            bob_pq_sig_public=remote_bundle.pq_sig_public,
            z_classical=initiation.shared_secret,
            z_pq=_z_pq,
        )
        # The Double Ratchet's first DH step uses the classical DH output,
        # computed exactly as in v1: DH(EK_A, SPK_B).
        start_dh = dh(initiation.ek_private, remote_bundle.spk_public)
        root_key, start_chain = root_chain(root_secret, start_dh)
        ratchet = DoubleRatchet(
            root_key,
            start_chain,
            initiation.ek_private,
            remote_bundle.spk_public,
            initiator=True,
        )
        return cls(True, initiation.ad, ratchet, initiation.init_payload)

    @classmethod
    def accept(cls, local: DeviceKeys, init_payload: bytes) -> E2EESession:
        """Build a responder session from an X3DH init payload (Bob, v1)."""
        acceptance = x3dh_respond(local, init_payload)
        root_key, start_chain = root_chain(
            acceptance.shared_secret,
            dh(local.spk_private, acceptance.initiator_ek_public),
        )
        ratchet = DoubleRatchet(
            root_key,
            start_chain,
            local.spk_private,
            acceptance.initiator_ek_public,
            initiator=False,
        )
        return cls(False, acceptance.ad, ratchet)

    @classmethod
    def accept_hybrid(
        cls,
        local: DeviceKeys,
        alice_ik_public: bytes,
        alice_pq_kem_public: bytes,
        alice_pq_sig_public: bytes,
        init_payload: bytes,
        decapsulate_fn,
    ) -> E2EESession:
        """Build a responder session for the hybrid (v2) handshake.

        ``decapsulate_fn(local_pq_kem_private, kem_ct)`` must return ``ss_pq``.
        """
        acceptance: HybridAcceptance = hybrid_x3dh_respond_v2(
            local=local,
            alice_ik_public=alice_ik_public,
            alice_pq_kem_public=alice_pq_kem_public,
            alice_pq_sig_public=alice_pq_sig_public,
            init_payload=init_payload,
            decapsulate_fn=decapsulate_fn,
        )
        # Same shape as v1: start the ratchet with DH(SPK_B, EK_A).
        start_dh = dh(local.spk_private, acceptance.initiator_ek_public)
        root_key, start_chain = root_chain(acceptance.root_secret, start_dh)
        ratchet = DoubleRatchet(
            root_key,
            start_chain,
            local.spk_private,
            acceptance.initiator_ek_public,
            initiator=False,
        )
        return cls(False, acceptance.ad, ratchet)

    def encrypt_message(self, plaintext: bytes, extra_ad: bytes = b"") -> bytes:
        return self._ratchet.encrypt_message(plaintext, self._ad + extra_ad)

    def decrypt_message(self, wire: bytes, extra_ad: bytes = b"") -> bytes:
        return self._ratchet.decrypt_message(wire, self._ad + extra_ad)

    def export_state(self) -> bytes:
        ad_bytes = self._ad
        header = _SESSION_STATE_STRUCT.pack(
            SESSION_STATE_VERSION,
            1 if self._initiator else 0,
            (len(ad_bytes) // 256),
            len(ad_bytes) % 256,
        )
        return header + ad_bytes + self._ratchet.export_state()

    @classmethod
    def from_state_bytes(cls, raw: bytes) -> E2EESession:
        if len(raw) < _SESSION_STATE_STRUCT.size:
            raise SessionError("malformed session state")
        version, is_initiator, ad_hi, ad_lo = _SESSION_STATE_STRUCT.unpack(
            raw[:_SESSION_STATE_STRUCT.size]
        )
        if version != SESSION_STATE_VERSION:
            raise SessionError(f"unsupported session state version {version}")
        ad_length = ad_hi * 256 + ad_lo
        ad_bytes = raw[
            _SESSION_STATE_STRUCT.size : _SESSION_STATE_STRUCT.size + ad_length
        ]
        if len(ad_bytes) != ad_length:
            raise SessionError("truncated session AD")
        ratchet = DoubleRatchet.from_state_bytes(
            raw[_SESSION_STATE_STRUCT.size + ad_length :]
        )
        return cls(bool(is_initiator), ad_bytes, ratchet)


def x25519_pub_of(priv: X25519PrivateKey) -> bytes:
    """Return the raw 32-byte X25519 public key for a private key."""
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


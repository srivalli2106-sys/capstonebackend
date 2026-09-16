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
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .kdf import root_chain
from .keys import (
    DeviceKeys,
    KeyBundle,
    dh,
)
from .ratchet import DoubleRatchet, RatchetError
from .x3dh import x3dh_initiate, x3dh_respond

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
        """Build an initiator session against a peer bundle (Alice)."""
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
    def accept(cls, local: DeviceKeys, init_payload: bytes) -> E2EESession:
        """Build a responder session from an X3DH init payload (Bob)."""
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

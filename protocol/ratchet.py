"""ratchet.py — the Double Ratchet (forward secrecy + tamper evidence).

The ratchet turns one X3DH root secret into an unbounded stream of messages,
each encrypted with a fresh key derived from a chain:

  * **DH ratchet** — every time the peer's ratchet public key changes, both
    sides do a root-key step over the new Diffie-Hellman output and start fresh
    sending/receiving chains. Old chain keys are never reused.
  * **Symmetric ratchet** — per message, ``KDF_CK`` moves the current chain one
    step forward and yields a unique message key.
  * **Skipped keys** — out-of-order messages are buffered as keyed-by
    ``(peer_dh, index)`` message keys so reordered delivery still decrypts,
    bounded by ``MAX_SKIP``.
  * **Replay protection** — a message older than the current receiving-chain
    position (not in the skip buffer) is rejected.

Wire framing of one ratchet message (embedded in the envelope's ``data``):

    version(1) | dh_public(32) | previous_chain_length(4) | chain_index(4)
               | AES-256-GCM ciphertext(+16 tag)

The AEAD associated data is the session's ``AD`` (the two X3DH identities)
concatenated with the exact header bytes, so tampering with either the payload
or the header fails decryption.
"""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import chain_step, derive_message_key, root_chain
from .keys import dh, x25519_private_from_bytes, x25519_private_raw, x25519_public_raw

MESSAGE_VERSION = 1
_HEADER_STRUCT = struct.Struct(">B 32s I I")
_HEADER_SIZE = _HEADER_STRUCT.size
_MAX_SKIP = 1000
MAX_RATCHET_MESSAGES = 1000

_STATE_VERSION = 1
_STATE_HEADER = struct.Struct(">B B 32s 32s 32s B I I I I")
_PRESENT = 0x01
_ABSENT = 0x00
_SKIP_ENTRY = struct.Struct(">32s I 32s")


class RatchetError(ValueError):
    """Raised on any ratchet misuse or failed decryption."""


class DecryptionError(RatchetError):
    """Raised when a message cannot be authenticated or is replayed."""


class Header:
    __slots__ = ("dh", "pn", "n")

    def __init__(self, dh: bytes, pn: int, n: int) -> None:
        self.dh = dh
        self.pn = pn
        self.n = n


class RatchetMessage:
    __slots__ = ("dh", "pn", "n", "ciphertext")

    def __init__(self, dh: bytes, pn: int, n: int, ciphertext: bytes) -> None:
        self.dh = dh
        self.pn = pn
        self.n = n
        self.ciphertext = ciphertext


def pack_header(header: Header) -> bytes:
    return _HEADER_STRUCT.pack(MESSAGE_VERSION, header.dh, header.pn, header.n)


def unpack_header(raw: bytes) -> Header:
    if len(raw) != _HEADER_SIZE:
        raise RatchetError("malformed ratchet header")
    version, dh_pub, pn, n = _HEADER_STRUCT.unpack(raw)
    if version != MESSAGE_VERSION:
        raise RatchetError(f"unsupported ratchet version {version}")
    return Header(dh_pub, pn, n)


def pack_message(header: Header, ciphertext: bytes) -> bytes:
    return pack_header(header) + ciphertext


def unpack_message(raw: bytes) -> RatchetMessage:
    if len(raw) < _HEADER_SIZE + 16:
        raise RatchetError("malformed ratchet message")
    header = unpack_header(raw[:_HEADER_SIZE])
    return RatchetMessage(header.dh, header.pn, header.n, raw[_HEADER_SIZE:])


class DoubleRatchet:
    """A single bidirectional ratchet between two devices.

    ``start_chain`` is the first chain key derived during X3DH (the chain
    going from the initiator to the responder). The initiator owns it as its
    sending chain; the responder owns it as its receiving chain. The opposite
    direction appears after the first DH ratchet.
    """

    def __init__(
        self,
        root_key: bytes,
        start_chain: bytes,
        local_dh: X25519PrivateKey,
        remote_dh: bytes,
        *,
        initiator: bool,
        max_skip: int = _MAX_SKIP,
    ) -> None:
        self._rk = root_key
        self._local_dh = local_dh
        self._remote_dh = remote_dh
        self._send_chain: bytes | None = start_chain if initiator else None
        self._recv_chain: bytes | None = start_chain if not initiator else None
        self._ns = 0
        self._nr = 0
        self._pn = 0
        self._max_skip = max_skip
        self._skipped: dict[tuple[bytes, int], bytes] = {}

    @property
    def local_public(self) -> bytes:
        return x25519_public_raw(self._local_dh)

    def encrypt_message(self, plaintext: bytes, ad: bytes) -> bytes:
        """Encrypt ``plaintext`` into one wire message."""
        if self._send_chain is None:
            self._generate_sending_chain()
        header = Header(self.local_public, self._pn, self._ns)
        wire_header = pack_header(header)
        self._send_chain, message_key = chain_step(self._send_chain)
        index = self._ns
        self._ns += 1
        aes_key, nonce = derive_message_key(message_key, index)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, ad + wire_header)
        return pack_message(header, ciphertext)

    def decrypt_message(self, wire: bytes, ad: bytes) -> bytes:
        """Decrypt one wire message, handling ratchet steps and reordering."""
        message = unpack_message(wire)

        if self._remote_dh is None or message.dh != self._remote_dh:
            self._skip_message_keys(message.pn)
            self._dh_ratchet(message.dh)

        skipped_key = self._skipped.pop((message.dh, message.n), None)
        if skipped_key is not None:
            message_key = skipped_key
        else:
            if self._recv_chain is None:
                raise DecryptionError("no receiving chain for this turn")
            if message.n < self._nr:
                raise DecryptionError("replayed or expired message index")
            if message.n > self._nr + self._max_skip:
                raise DecryptionError("message index too far ahead")
            while self._nr < message.n:
                self._recv_chain, mk = chain_step(self._recv_chain)
                self._buffer_skipped(mk, self._nr)
                self._nr += 1
            self._recv_chain, message_key = chain_step(self._recv_chain)
            self._nr += 1

        aes_key, nonce = derive_message_key(message_key, message.n)
        wire_header = wire[:_HEADER_SIZE]
        try:
            return AESGCM(aes_key).decrypt(nonce, message.ciphertext, ad + wire_header)
        except InvalidTag as exc:
            raise DecryptionError("message authentication failed") from exc

    def _generate_sending_chain(self) -> None:
        """Create the first sending chain when none exists.

        The initiator has one from the X3DH setup; the responder does not and
        must NOT reuse the initial DH pair (that would desynchronize the root
        chain). This advances to a fresh ratchet key in a single root step,
        exactly mirroring what the peer computes when it sees the new public
        key — which keeps the root key, and every later ratchet, symmetric.
        """
        if self._remote_dh is None:
            raise RatchetError("cannot send without a remote ratchet key")
        fresh = X25519PrivateKey.generate()
        self._rk, self._send_chain = root_chain(
            self._rk, dh(fresh, self._remote_dh)
        )
        self._local_dh = fresh
        self._pn = self._ns
        self._ns = 0

    def _dh_ratchet(self, new_remote_dh: bytes) -> None:
        self._pn = self._ns
        self._ns = 0
        self._nr = 0
        self._remote_dh = new_remote_dh
        self._rk, self._recv_chain = root_chain(
            self._rk, dh(self._local_dh, new_remote_dh)
        )
        self._local_dh = X25519PrivateKey.generate()
        self._rk, self._send_chain = root_chain(
            self._rk, dh(self._local_dh, new_remote_dh)
        )

    def _skip_message_keys(self, up_to: int) -> None:
        """Buffer receiving-chain keys up to ``up_to`` (older messages from
        this DH turn may still arrive out of order)."""
        if self._recv_chain is None:
            return
        if up_to > self._nr + self._max_skip:
            raise DecryptionError("skip bound exceeded")
        while self._nr < up_to:
            self._recv_chain, mk = chain_step(self._recv_chain)
            self._buffer_skipped(mk, self._nr)
            self._nr += 1

    def _buffer_skipped(self, message_key: bytes, index: int) -> None:
        if len(self._skipped) >= self._max_skip:
            raise DecryptionError("skip buffer exhausted")
        self._skipped[(self._remote_dh, index)] = message_key

    def export_state(self) -> bytes:
        skip_entries = b"".join(
            _SKIP_ENTRY.pack(remote, index, key)
            for (remote, index), key in sorted(self._skipped.items())
        )
        header = _STATE_HEADER.pack(
            _STATE_VERSION,
            1 if self._send_chain is not None else 0,
            self._rk,
            x25519_private_raw(self._local_dh),
            self._remote_dh if self._remote_dh is not None else b"\x00" * 32,
            1 if self._recv_chain is not None else 0,
            self._ns,
            self._nr,
            self._pn,
            self._max_skip,
        )
        body = b"".join(
            (
                self._send_chain if self._send_chain is not None else b"\x00" * 32,
                self._recv_chain if self._recv_chain is not None else b"\x00" * 32,
                struct.pack(">I", len(skip_entries)),
                skip_entries,
            )
        )
        return header + body

    @classmethod
    def from_state_bytes(cls, raw: bytes) -> DoubleRatchet:
        if len(raw) < _STATE_HEADER.size:
            raise RatchetError("malformed ratchet state")
        version, has_send, rk, local_priv, remote_dh, has_recv, ns, nr, pn, max_skip = (
            _STATE_HEADER.unpack(raw[:_STATE_HEADER.size])
        )
        if version != _STATE_VERSION:
            raise RatchetError(f"unsupported ratchet state version {version}")
        body = raw[_STATE_HEADER.size:]
        if len(body) < 32 + 32 + 4:
            raise RatchetError("malformed ratchet state body")
        send_raw, recv_raw, skip_len = (
            body[:32],
            body[32:64],
            struct.unpack(">I", body[64:68])[0],
        )
        skip_raw = body[68:]
        if len(skip_raw) != skip_len:
            raise RatchetError("malformed skipped-key buffer")

        skipped: dict[tuple[bytes, int], bytes] = {}
        for offset in range(0, skip_len, _SKIP_ENTRY.size):
            if offset + _SKIP_ENTRY.size > skip_len:
                raise RatchetError("truncated skipped-key buffer")
            remote, index, key = _SKIP_ENTRY.unpack(
                skip_raw[offset : offset + _SKIP_ENTRY.size]
            )
            skipped[(remote, index)] = key

        ratio: DoubleRatchet = cls.__new__(cls)
        ratio._rk = rk
        ratio._local_dh = x25519_private_from_bytes(local_priv)
        ratio._remote_dh = remote_dh if remote_dh != b"\x00" * 32 else None
        ratio._send_chain = send_raw if has_send else None
        ratio._recv_chain = recv_raw if has_recv else None
        ratio._ns = ns
        ratio._nr = nr
        ratio._pn = pn
        ratio._max_skip = max_skip
        ratio._skipped = skipped
        return ratio

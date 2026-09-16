"""kdf.py — key derivation for the Double Ratchet (HKDF-SHA256).

Three derivation steps, each domain-separated with a literal info string so
keys from different stages can never be confused:

  * ``root_chain(rk, dh_out)`` — the root/key-chain step: hkdf over the DH
    output produces a new root key and the first chain key for that direction.
  * ``chain_step(ck)`` — advances a chain key by one message, yielding the next
    chain key and a message key.
  * ``derive_message_key(mk, index)`` — expands a message key into an
    AES-256-GCM key + 12-byte nonce; ``index`` is bound into the info to make
    nonce reuse impossible.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT_INFO = b"secure-messaging-dr-root-v1"
CHAIN_INFO = b"secure-messaging-dr-chain-v1"
MESSAGE_INFO = b"secure-messaging-dr-message-v1"

HASH = hashes.SHA256
_ROOT_LENGTH = 64
_MESSAGE_KEY_LENGTH = 32
_NONCE_LENGTH = 12


def _hkdf(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    return HKDF(
        algorithm=HASH(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def root_chain(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Root ratchet: ``(new_root, first_chain) = HKDF(root, dh, 64).``"""
    material = _hkdf(
        ikm=dh_output,
        salt=root_key,
        info=ROOT_INFO,
        length=_ROOT_LENGTH,
    )
    return material[:32], material[32:]


def chain_step(chain_key: bytes) -> tuple[bytes, bytes]:
    """Advance a chain: ``(next_chain, message_key) = HKDF(chain).``"""
    material = _hkdf(
        ikm=chain_key,
        salt=b"",
        info=CHAIN_INFO,
        length=_ROOT_LENGTH,
    )
    return material[:32], material[32:]


def derive_message_key(message_key: bytes, index: int) -> tuple[bytes, bytes]:
    """Expand a message key into ``(aes_key, nonce)`` bound to ``index``."""
    if index < 0:
        raise ValueError("index must be >= 0")
    nonce = _hkdf(
        ikm=message_key,
        salt=b"",
        info=MESSAGE_INFO + index.to_bytes(8, "big"),
        length=_MESSAGE_KEY_LENGTH + _NONCE_LENGTH,
    )
    return nonce[:_MESSAGE_KEY_LENGTH], nonce[_MESSAGE_KEY_LENGTH:]

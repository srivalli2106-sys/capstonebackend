# Double Ratchet

The Double Ratchet (Signal-style, symmetric turn) turns the X3DH root secret
into an unbounded stream of messages, each encrypted with a fresh key. Both
implementations are byte-compatible: frontend `src/crypto/doubleRatchet.ts`
and backend `protocol/ratchet.py`, pinned by shared test vectors.

## Wire framing of one ratchet message

```
version(1) | dh_public(32) | previous_chain_length(4, BE) | chain_index(4, BE)
           | AES-256-GCM ciphertext(+16-byte tag)
```

- Fixed header size: 41 bytes (`1 + 32 + 4 + 4`).
- `dh_public` is the sender's current ratchet public key; a change of this
  value triggers a DH ratchet step on the receiver.
- `previous_chain_length` (`pn`) is the number of messages sent in the
  previous sending chain; `chain_index` (`n`) is the message index in the
  current chain.
- The whole frame is base64url-encoded as the `data` of a `text` (or `file`)
  envelope.

## Key derivation (HKDF-SHA256)

Three domain-separated steps, all literally labeled so keys from different
stages cannot be confused:

```
ROOT_INFO   = "secure-messaging-dr-root-v1"
CHAIN_INFO  = "secure-messaging-dr-chain-v1"
MESSAGE_INFO = "secure-messaging-dr-message-v1"
```

```
root_chain(root, dh_out):
    material = HKDF(ikm=dh_out, salt=root, info=ROOT_INFO, 64)
    return material[0:32], material[32:64]           # (new_root, first_chain)

chain_step(chain):
    material = HKDF(ikm=chain, salt=b"", info=CHAIN_INFO, 64)
    return material[0:32], material[32:64]           # (next_chain, message_key)

derive_message_key(message_key, index):
    out = HKDF(ikm=message_key, salt=b"", info=MESSAGE_INFO || index_be8, 44)
    return out[0:32], out[32:44]                     # (aes_key, 12-byte nonce)
```

Binding `index` into the message-key info makes nonce reuse impossible: the
same expanded key never yields a nonce for two different indices.

## AEAD

- Primitive: AES-256-GCM, 12-byte nonce, 16-byte tag (128-bit).
- Associated data is the session `AD` (the two X3DH identity publics)
  concatenated with the EXACT wire header bytes:

```
aead_ad = session_ad || wire_header_bytes
```

Tampering with the payload OR the header fails the AEAD tag check.

## Send path

```
if no sending chain yet: generate one (see asymmetric start below)
header = (version=1, local_ratchet_public, pn, ns)
advance chain -> message_key
expand message_key(index=ns) -> (aes_key, nonce)
ciphertext = AES-GCM(aes_key, nonce).encrypt(plaintext, ad + wire_header)
ns += 1
```

## Receive path

```
unpack header; validate version; require len >= header(41) + tag(16)
if header.dh != remote_ratchet_public:
    skip message keys up to pn          (older out-of-order messages still decrypt)
    dh_ratchet(header.dh)               (new root key + fresh send/recv chains)
if (header.dh, n) in skipped_keys:
    use the buffered message key
else:
    require a receiving chain
    if n < nr: reject (replayed / expired index)
    if n > nr + MAX_SKIP (1000): reject (too far ahead)
    buffer skipped keys for nr..n-1
    advance the receiving chain to n; nr = n + 1
decrypt with AES-GCM(ad + wire_header); InvalidTag -> "message authentication failed"
```

Out-of-order and pre-key-rotation messages decrypt through a bounded skipped-key
buffer (`MAX_SKIP = 1000`); everything outside it is rejected. A message index
older than the current receive position (and not in the buffer) is a replay
and is rejected.

## DH ratchet step

When the peer's ratchet public key changes:

```
pn = ns; ns = 0; nr = 0
remote_ratchet = new_public
root, recv_chain = root_chain(root, DH(local_ratchet_priv, new_remote_public))
generate fresh local ratchet keypair
root, send_chain = root_chain(root, DH(fresh_priv, new_remote_public))
```

Old chain keys are never reused, which is what provides forward secrecy.

## Asymmetric start

The initiator owns the first sending chain after bootstrap; the responder
starts with that same value as its receiving chain. The responder's first
send advances to a fresh ratchet key in a single root step (it must NOT reuse
the initial DH pair, which would desynchronize the root chain). The initiator
computes the identical value when it sees the responder's new public key, so
every later ratchet is symmetric.

## State export / import

Both implementations can export and restore ratchet state:

- Backend (`protocol/ratchet.py`): header struct `>B B 32s 32s 32s B I I I I`
  (115 bytes) plus a body of send-chain(32) + recv-chain(32) + skip-length(4)
  + skip entries (`>32s I 32s`, 68 bytes each). Versioned; unsupported
  versions and truncated skip buffers are rejected.
- Frontend (`src/crypto/doubleRatchet.ts`): `STATE_HEADER_SIZE = 115`,
  `STATE_BODY_MIN = 68`, same layout with `RATCHET_STATE_VERSION = 1`.

These formats exist for determinism tests and future persistence; in the
running application sessions are memory-only and state is never persisted
(see `SESSION_MANAGEMENT.md` and `LIMITATIONS.md`).

## Constants at a glance

| Constant | Value |
| --- | --- |
| `RATCHET_MESSAGE_VERSION` / `MESSAGE_VERSION` | 1 |
| `HEADER_SIZE` | 41 |
| `MAX_SKIP` | 1000 |
| root HKDF length | 64 |
| message key / AES key | 32 |
| nonce | 12 |
| AEAD tag | 16 |
# End-to-End Encryption Protocol (X3DH + Double Ratchet)

Reference implementation (Phase 13) in the pure-Python `protocol/` package.
This repository is the **server side**: it relays opaque `data` blobs and never
runs this crypto. A client implementation can be validated against this spec
and the package's unit tests.

> ⚠️ Security note: this is a reference implementation for a learning / demo
> project. It is **not** an audited, production-grade cryptographic library.

---

## 1. Key material

| Key | Algorithm | Role |
|-----|-----------|------|
| `IK` (identity) | Ed25519 | Long-term device identity. The **public** key (`ik_public`) is registered with the server at auth time and included in the key bundle so peers can verify the signed prekey. |
| `IKX` (X3DH identity) | X25519 | Long-term key used in the X3DH DH computations. |
| `SPK` (signed prekey) | X25519 | Semi-static prekey, replaced periodically. |
| `OPK` (one-time prekey) | X25519 | Single-use prekeys; each X3DH run consumes exactly one. |
| `EK` (ephemeral) | X25519 | Fresh per-session ephemeral. |

The signed prekey is bound to the Ed25519 identity:

```
SPK_signature = Ed25519_sign(IK_secret, SPK_SIGN_CONTEXT || SPK_public_32bytes)
```

`SPK_SIGN_CONTEXT = b"secure-messaging-spk-sign-v1"` (in `protocol/keys.py`).
Verification lets the initiator prove the SPK belongs to the claimed device
identity, defeating active substitution of prekeys mid-session.

## 2. Key bundle

A `KeyBundle` (`protocol/keys.py`, `build_key_bundle`) holds:

```
ik_public        (Ed25519 public, 32 bytes)
xdh_public       (X25519 public, 32 bytes)   # the X3DH identity IKX
spk_public       (32 bytes)
spk_signature    (64 bytes)
opk_publics      (one or more 32-byte one-time prekeys)
```

Server integration (`/keys/upload`, `/keys/bundle/{user_id}`): the SPK, its
signature, and a single OPK are uploaded and stored; fetching a bundle
consumes the OPK atomically so each fetch yields a fresh one-time prekey.
The bundle also exposes the registered `ik_public` (from the users
collection) so the initiator can verify `spk_signature`.

## 3. X3DH setup (`protocol/x3dh.py`)

Initiator (**Alice**) holds Bob's bundle and picks Alice's identity `IKX_A` +
a fresh ephemeral `EK_A`. Shared secret, using the RFC-style DH term order:

```
SK = HKDF-SHA256(
        DH(IKX_A, SPK_B)  || DH(EK_A, IKX_B) || DH(EK_A, SPK_B) || DH(EK_A, OPK_B),
        salt = None,
        info = b"secure-messaging-x3dh-v1",
        length = 32)
```

When no OPK is available (index `0xFF`), the last DH term is omitted.

**Initiation frame** sent to Bob as `session_init`:

```
byte 0        version (1)
bytes 1..32   IKX_A
bytes 33..64  EK_A
byte 65       OPK index used (0xFF = none)
```

**Associated data** (used as the session AD, and as the AEAD `session_ad` in
§5): `AD = IKX_A_public || IKX_B_public` (64 bytes).

Responder (**Bob**) recomputes the same shared secret from his stored private
keys and the initiator's public keys (`x3dh_respond`, `protocol/x3dh.py`).
`Acceptance` carries the shared SK, the AD, and Bob's view of the initiator.
The init frame is bound into Bob's session so a replayed or substituted frame
cannot produce Bob's SK (the resulting session simply will not decrypt).

## 4. Double Ratchet (`protocol/ratchet.py`, `protocol/kdf.py`)

Bidirectional, symmetric-turn ratchet over the X3DH shared secret.

```
root_key, chain = root_chain(SK, DH(EK_A, SPB_B))      # initiator's 1st chain
Bob (responder): same root/chain starter from x3dh_respond's SK and
                  DH(SPK_B_private, EK_A_public).
```

- The chain shared after setup runs **initiator → responder**. The initiator
  holds it as its *sending* chain; the responder as its *receiving* chain.
- The responder's **first send** must not reuse the initial DH pair — it
  advances to a fresh ratchet key in a single root step
  (`_generate_sending_chain`), exactly mirroring the initiator's DH ratchet
  when the new public key arrives. This keeps the root key — and every later
  turn — symmetric.
- Every subsequent turn uses the two-step DH ratchet
  (`_dh_ratchet`): derive the receiving chain from the new remote public key,
  then generate a fresh local key and derive the next sending chain.

KDFs (`protocol/kdf.py`, all HKDF-SHA256):

```
root_chain(rk, dh_out)        -> (rk', chain)
chain_step(ck)                -> (ck', mk)
derive_message_key(mk, index) -> (aes_key, nonce)
```

- Message key = AES-256-GCM; the 12-byte nonce is derived from and bound to
  the message index (no nonce reuse across ratchet keys).
- Out-of-order delivery: message keys are buffered in a **skipped-key buffer**
  keyed by `(remote_dh_public, index)`, bounded by `MAX_SKIP = 1000`. Indices
  older than the previous message (`nr`) are rejected as replayed/expired;
  indices beyond `nr + MAX_SKIP` are rejected.
- Skip across DH turns is supported via the header's previous-chain-length
  `pn` (keys from the previous sending chain are pre-skipped).

Wire message (`protocol/ratchet.py`, `pack_message`):

```
byte 0        version (1)
bytes 1..32   DH public key for this turn
bytes 33..36  pn (previous chain length, big-endian)
bytes 37..40  n  (message index in this chain, big-endian)
bytes 41..    AES-256-GCM ciphertext (16-byte tag included)
```

`AD` of the AEAD = `session_ad || extra_ad || wire_header_bytes`. The full 41
header bytes are authenticated, so `dh`/`pn`/`n` cannot be tampered with.

## 5. Session (`protocol/session.py`)

`E2EESession`:

| Method | Use |
|--------|-----|
| `E2EESession.initiate(local=DeviceKeys, remote_bundle=KeyBundle, opk_index=...)` | Alice: build a sender session; returns the session whose `.init_payload` is the `session_init` frame. |
| `E2EESession.accept(local=DeviceKeys, init_payload=bytes)` | Bob: build the receiving session from an init frame. |
| `encrypt_message(plaintext, extra_ad=b"")` | `data = session_ad || extra_ad` becomes the AEAD AD; returns wire message. |
| `decrypt_message(wire, extra_ad=b"")` | Returns plaintext or raises `DecryptionError`. |
| `export_state()` / `from_state_bytes()` | Serialize/resume a session (e.g., app restart). Versioned binary framing; round-trips the ratchet (incl. skipped keys) exactly. |

`extra_ad` lets the enclosing application bind envelope context (e.g., the
message `id`, sender/recipient) into the AEAD.

## 6. Server integration (this repository)

- `protocol/` is compiled into neither the server runtime nor the Docker
  image; it is a spec/reference + unit-test target (`pytest --cov=protocol`).
- The server's `/keys/*` endpoints move the *material* the protocol needs:
  upload SPK+signature+OPK, consume an OPK on bundle fetch, and expose
  `ik_public` for signature verification.
- `session_init` / `session_accept` envelope types are reserved in the message
  type catalog (`docs/PROTOCOL.md` §4); `data` stays opaque, so transport,
  ordering, and replay handling are unchanged.

## 7. Threat-model notes

- **Forward secrecy:** each message uses a fresh key; a compromise of long-term
  or root keys never decrypts past messages (post-compromise security via the
  DH ratchet).
- **Identity binding:** the SPK signature prevents prekey substitution without
  the device's identity.
- **Replay:** message indices + per-turn DH publics; older message keys are
  dropped rather than accepted. Application-level idempotency additionally
  uses the 26-char ULID message id.
- **Audit state:** this package is the current best-effort reference; a
  production deployment must commission an independent crypto review.
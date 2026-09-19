# X3DH

X3DH (Signal-style extended triple Diffie-Hellman) establishes a shared
secret between two devices using the peer's X25519 identity key and prekeys.
Both implementations (frontend `src/crypto/x3dh.ts` and backend
`protocol/x3dh.py`) are byte-compatible and are pinned by cross-implementation
test vectors.

## Key material involved

| Key | Held by | Role in X3DH |
| --- | --- | --- |
| `IKX_A` | initiator device | Alice's X25519 identity (the bundle's `xdh_public`) |
| `IKX_B` | responder device | Bob's X25519 identity |
| `EK_A` | initiator, ephemeral | fresh X25519 key per session |
| `SPK_B` | responder | Bob's signed prekey (verified via his Ed25519 auth key) |
| `OPK_B` | responder | one-time prekey, single use, optional |

## Shared secret

```
SK = HKDF-SHA256(
       DH(IKX_A, SPK_B) || DH(EK_A, IKX_B) || DH(EK_A, SPK_B) || [DH(EK_A, OPK_B)],
       salt = b"",
       info = b"secure-messaging-x3dh-v1",
       length = 32)
```

The OPK term is included only when a one-time prekey was available. Each DH
term is a raw 32-byte X25519 shared secret, concatenated in this exact order.
The initiator computes it directly; the responder recomputes the same four
terms from its private keys (`DH(SPK_B, IKX_A) == DH(IKX_A, SPK_B)`, etc).

Constants: `X3DH_INFO = "secure-messaging-x3dh-v1"`, output length 32 bytes,
`INIT_VERSION = 1`, `NO_OPK_INDEX / NO_OPK = 0xFF`.

## Associated data (AD)

```
AD = IKX_A_public || IKX_B_public     (64 bytes)
```

The two X3DH identity public keys are concatenated. AD is later bound into
every Double Ratchet AEAD operation, so a ciphertext cannot be redirected to
any other peer.

## Initiation frame

The initiator ships its identity and ephemeral public keys inside a fixed
66-byte binary frame:

```
version(1) | IKX_A(32) | EK_A(32) | opk_index(1)
```

- `version` is 1. Anything else is rejected (`unsupported_version`).
- `opk_index` is the index of the OPK that was used, or `0xFF` when no OPK
  was used.
- Built with `>` big-endian struct `>B 32s 32s B` on the backend and a byte
  array on the frontend.
- On the wire it is base64url-encoded into a `session_init` envelope's
  `data` field.

## Initiator steps (`x3dhInitiate`)

1. Validate all inputs are 32/64 bytes.
2. Verify the SPK binding: `Ed25519.verify(spk_sig, "secure-messaging-signed-prekey-v1" || spk_public, ik_public)`. Failure raises `invalid_signature`.
3. If the bundle has no `xdh_public` (IKX_B), raise `missing_ikx` (the client
   does not fabricate key material).
4. Generate ephemeral `EK_A` (injectable for deterministic tests).
5. Compute the four DH terms and `SK`, build `AD`, build the init frame.

## Responder steps (`x3dhRespond` / `x3dh_respond`)

1. Parse the init frame (exact length, version check).
2. Resolve the referenced OPK private key by index; missing index -> error.
3. Recompute the DH terms from `SPK_B`/`IKX_B` privates and the carried
   `IKX_A`/`EK_A` publics, then `SK` and `AD`.
4. Return the consumed OPK index (the one-time prekey is gone after this).

## Session bootstrap

The X3DH result seeds the Double Ratchet:

```
root_key     = SK                        (32 bytes)
initiating_chain = HKDF? No: from ratchetKdf.x3dhRootAndChain(SK)
```

In this implementation the root chain is started with a single
`root_chain(SK, dh_output)` step where the first DH output binds each side's
ratchet key (see `DOUBLE_RATCHET.md`):

- The initiator generates a fresh ratchet keypair and computes
  `root_chain(SK, DH(ratchet_priv, remote_ratchet_pub))`, yielding
  `(root_key, sending_chain)`. The responder mirrors this computation when it
  sees the initiator's ratchet public in the first message header.

The `E2EESession.initiate`/`accept` wrappers in `src/crypto/e2eeSession.ts`
perform this bootstrap and hold the resulting ratchet state.

## Failure modes

| Error | Meaning |
| --- | --- |
| `invalid_payload` | init frame wrong length |
| `unsupported_version` | frame version != 1 |
| `invalid_signature` | SPK signature verification failed |
| `missing_ikx` | bundle lacks the X25519 identity key |
| `invalid_ephemeral` / `invalid_bundle` | key material malformed |
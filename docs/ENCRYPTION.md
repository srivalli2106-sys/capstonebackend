# Encryption

This document catalogues every cryptographic primitive used in the system,
where it lives, and how it is keyed.

## Primitive inventory

| Primitive | Use | Frontend | Backend |
| --- | --- | --- | --- |
| AES-256-GCM | symmetric message + key wrap | Web Crypto (`crypto/aead.ts`) | `cryptography` AESGCM |
| X25519 | X3DH DH + ratchet DH | `crypto/x25519.ts` (`@noble/curves`) | `protocol/keys.py` |
| Ed25519 | auth identity, SPK signatures | `crypto/ed25519.ts` (`@noble/curves`) | `protocol/keys.py` |
| HKDF-SHA256 | root/chain/message derivation | `crypto/ratchetKdf.ts` | `protocol/kdf.py` |
| PBKDF2-SHA256 | key stretching for the identity seed | Web Crypto (`crypto/kdf.ts`) | n/a (seed is local-only) |
| SHA-256 | hashes inside HKDF/PBKDF2 | Web Crypto / noble | `cryptography` |

## Encryption in use (AES-256-GCM)

- 256-bit key, 12-byte nonce, 128-bit authentication tag.
- `EncryptedBlob` = `{ ivHex, ciphertextHex }` (tag appended to ciphertext).
- Nonces are 96 random bits per operation (`randomIv()`); the message-key path
  in the Double Ratchet instead derives the nonce from the message index so
  reuse is structurally impossible.

## Where AES-GCM is applied

1. **Identity seed** (at-rest, local): the 256-bit Ed25519/X25519 device seed
   is encrypted with a key derived from the user's passphrase and stored in
   IndexedDB. `AES_KEY_BYTES = 32`, `AES_IV_BYTES = 12`, `AES_TAG_BYTES = 16`.
2. **Device key secrets** (at-rest, local): the freshly derived device seed is
   re-wrapped under a key derived from the user's passphrase. AD binds each
   record to the user ID.
3. **Messages**: every ratchet message is AES-256-GCM under a per-message key.
   Associated data binds the header bytes and the session's X3DH identities.

## Key derivation

### Passphrase to key (`crypto/kdf.ts`)

```
key = PBKDF2-SHA256(passphrase, salt, iterations=600,000, keybits=256)
```

- Salt: 16 random bytes per record, stored in the clear.
- `600_000` iterations (OWASP-recommended ballpark), on the unlock path only.
- Two conceptually separate keys are derived per login:
  - `identityKey`: unlocks the stored identity, then derives the device seed.
  - The re-wrapped device-key blob is decrypted with the passphrase-derived
    key.

### HKDF tree

Keys below are domain-separated so a key from one stage can never feed
another stage's inputs:

```
X3DH: SK = HKDF(DH terms, salt="", info="secure-messaging-x3dh-v1", 32)
   -> root = SK
Double Ratchet:
   -> root_chain(...)   info="secure-messaging-dr-root-v1"    64 (root|chain)
   -> chain_step(...)   info="secure-messaging-dr-chain-v1"   64 (chain|mk)
   -> expand(...)       info="secure-messaging-dr-message-v1" || index  44 (key|nonce)
```

## Digital signatures

- **Proof of possession (login)**: the client signs the server-issued nonce
  with its registered Ed25519 auth key (`Ed25519.sign(nonce_raw)` over the raw
  32-byte nonce). The server verifies against `ik_public`.
- **Signed prekey binding**: 
  ```
  spk_signature = Ed25519.sign(UTF8("secure-messaging-signed-prekey-v1") || spk_public, auth_seed)
  ```
  verified against `ik_public`. Ensures the peer's signed prekey really
  belongs to the same device identity it claims.

## Key sizes

| Material | Size |
| --- | --- |
| Ed25519 / X25519 public, private, seed | 32 bytes |
| Ed25519 signature | 64 bytes |
| AES key / aead key | 32 bytes |
| nonce | 12 bytes |
| AEAD tag | 16 bytes |
| PBKDF2 salt | 16 bytes |

## Full-chain summary

```
 passphrase + salt --PBKDF2--> passkey
 passkey --unlock--> device seed (Ed25519 + X25519 identity + prekeys)
 ik_public --register--> server (auth proof)
 device seed --derive--> signed prekey + bundle --> /keys/upload
 peer bundle + own seed --X3DH--> SK --> ratchet root
 ratchet root --root_chain--> per-turn chains --chain_step--> per-msg keys
 per-msg key --derive_message_key--> AES-256-GCM key + nonce -> ciphertext
```

## Notes

- All randomness comes from the platform CSPRNG (Web Crypto `getRandomValues`,
  `secrets`/`os.urandom` server-side).
- The server never sees plaintext, message keys, or chain state; envelopes are
  opaque blobs end to end.
- Backend-side key material appears only in `protocol/` and is used for
  tests/vectors; production message flows are encrypted client-to-client.
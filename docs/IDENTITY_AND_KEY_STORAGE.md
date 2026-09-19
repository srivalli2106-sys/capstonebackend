# Identity and Key Storage

## Local identity lifecycle (frontend)

An account is a user_id bound to a self-generated Ed25519 identity key. The
private seed and the X25519 device keys never leave the browser except as
ciphertext.

| Step | Action |
| --- | --- |
| Register | `createLocalIdentity(userId, passphrase)` generates the Ed25519 seed, generates X25519 device keys, derives an AES key from the passphrase + salt, encrypts both payloads, and writes the record to IndexedDB. The backend registration happens in `AuthController.register` only after the record exists. |
| Login / unlock | `unlockIdentity(userId, passphrase)` reads the record, re-derives the AES key, decrypts the seed and device keys, and returns an `UnlockedIdentity` that can sign nonces and expose device key material. |
| Lock | `unlocked.lock()` zero-fills the seed and device-key buffers and drops references (JS cannot guarantee heap erasure; this is best-effort). |
| Wipe | `deleteLocalIdentity(userId)` removes the record after explicit user confirmation. |

Old pre-Phase-4 records without an `enc_device_keys` envelope get device keys
provisioned lazily on first unlock and persisted immediately.

## IndexedDB schema

Database `secure-messaging`, object store `identities`, keyPath `user_id`,
schema version 1. One record per user_id.

Fields of a record:

| Field | Value |
| --- | --- |
| `user_id` | primary key, bound to the backend account id |
| `ik_public` | 64-hex Ed25519 public key registered with the backend |
| `created_at` | epoch ms |
| `schema_version` | 1 |
| `enc_seed` | encrypted seed envelope |
| `enc_device_keys` | encrypted device-keys envelope (optional, lazy provisioned) |

Envelope format (both `enc_seed` and `enc_device_keys`):

| Field | Value |
| --- | --- |
| `record_version` | 1 |
| `kdf` | `pbkdf2-sha256` |
| `iterations` | 600000 |
| `salt_hex` | per-record 16 random bytes |
| `iv_hex` | per-encryption 12 random bytes |
| `ciphertext_hex` | AES-256-GCM output (ciphertext + 16-byte tag) |

## Encryption details

- Key derivation (KDF): PBKDF2 with SHA-256, 600,000 iterations, 256-bit
  output, 16-byte salt, per Web Crypto. OWASP 2023 recommended strength.
  Rationale recorded in `src/crypto/kdf.ts` (Argon2id would need a WASM
  dependency and is out of scope).
- Cipher: AES-256-GCM with a fresh 12-byte IV per encryption and a 128-bit tag.
- The plaintext Ed25519 seed is encrypted with associated data
  `"secure-messaging-identity-v1" || 0x1F || user_id`, so a ciphertext cannot
  be replayed or moved to another account.
- The device-keys payload is a versioned binary blob (version byte + IKX
  private + SPK private + OPK presence flag + OPK private) encrypted under a
  DIFFERENT associated-data context, `"secure-messaging-device-keys-v1" ||
  user_id`, so the two ciphertexts are domain-separated. See
  `serializeDeviceKeys` in `src/crypto/deviceKeys.ts`.

## JWT storage

- JWT and user_id live in `sessionStorage` (`secure-messaging:jwt`,
  `secure-messaging:user_id`), cleared on tab close.
- `localStorage` is deliberately avoided (longer-lived, larger XSS blast
  radius). HTTP-only cookies are not used because the backend has no cookie
  auth path.
- Token bytes are never logged.

## The identity never lands on disk in plaintext

The only values persisted are the ciphertext, salt, IV, KDF parameters, and
public key halves. The decrypted seed is held in a single function scope and
released (zero-filled) when the caller invokes `lock()`.

## KeyController

`KeyController` depends on the unlocked identity held by `AuthController`. On
identity unlock it derives the public bundle (IKX, SPK, SPK signature, OPK)
and best-effort uploads it via `POST /keys/upload`. Status is one of
`not_provisioned` or `ready { local }`. Private scalars never leave the JS
heap and are dropped on identity lock.
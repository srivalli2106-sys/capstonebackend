# Key Management

## Key types

| Key | Domain | Size | Purpose | Owner |
| --- | --- | --- | --- | --- |
| IK | Ed25519 | 32 bytes public | Auth identity; registers as `ik_public`; signs the SPK binding and PoP nonces | generated once per account on the client |
| IKX | X25519 | 32 bytes | X3DH identity key (`xdh_public`), used in the DH terms | generated per device on the client |
| SPK | X25519 | 32 bytes | Signed prekey, rotated periodically | client |
| OPK | X25519 | 32 bytes | One-time prekey, single use | client, one at a time |

Hex encodings on the wire: keys 64 hex chars (32 bytes), signatures 128 hex
chars (64 bytes).

The Ed25519 (IK) and X25519 (IKX) domains are deliberately separate; an
Ed25519 seed is never used as an X25519 scalar.

## Signed prekey binding

Must match between frontend and backend exactly:

```
SPK_SIGN_CONTEXT = "secure-messaging-signed-prekey-v1"
signature = Ed25519.sign(UTF8(SPK_SIGN_CONTEXT) || spk_public_raw_32bytes, auth_seed)
```

- `src/crypto/deviceKeys.ts` exports `SPK_SIGN_CONTEXT` and
  `signSignedPrekey`; the backend `protocol/keys.py` verifies the same
  bytes when a peer validates a bundle.
- Peers verify this signature with the bundle's `ik_public` before trusting
  the SPK in an X3DH exchange.

## Bundle upload

`POST /keys/upload` (Bearer JWT required):

```json
{
  "xdh_public": "<64 hex>",
  "spk_public": "<64 hex>",
  "spk_sig": "<128 hex>",
  "opk_public": "<64 hex>" | null
}
```

Backend validation (`key_service.upload`):

- hex decode must succeed for non-null values;
- `xdh_public`, `spk_public`, `opk_public` must decode to 32 bytes;
- `spk_sig` must decode to 64 bytes;
- the user must already exist (404 otherwise).

The bundle is upserted into MongoDB `key_bundles`; `version` is incremented
on each upsert so consumers can detect rotation.

## Bundle retrieval and OPK consumption

`GET /keys/bundle/{user_id}` (Bearer JWT required):

```json
{
  "user_id": "bob",
  "ik_public": "<64 hex>",
  "xdh_public": "<64 hex>",
  "spk_public": "<64 hex>",
  "spk_sig": "<128 hex>",
  "opk_public": "<64 hex>" | null,
  "version": 2
}
```

- 404 `not_found` when the user or their bundle does not exist.
- The served OPK is CONSUMED atomically at the database level
  (`key_repository.consume_opk`): exactly one of any concurrent fetches
  receives the available prekey; everyone else sees `null`. This preserves
  the one-time property of OPKs under race conditions.
- `ik_public` rides along so the X3DH initiator can verify the SPK signature.
- `xdh_public` is served so the initiator can compute `DH(EK_A, IKX_B)` and
  bind the session AD to the two X3DH identities.

`GET /keys/prekeys/{user_id}` returns `{ user_id, opk_available, version }`.

## Frontend KeyController behavior

- On identity unlock, `KeyController.refresh()` publishes the bundle. The
  upload is a no-op when no JWT is held and is guarded against overlapping
  uploads.
- One OPK is generated/provisioned at a time (the backend stores at most one);
  `INITIAL_OPK_COUNT = 1`. The OPK is not replenished automatically after
  consumption in the current build (see `LIMITATIONS.md`).
- Private scalars are held only in the unlocked identity and are zero-filled
  on lock. Only public hex values ever appear in request bodies.

## Bundle format details

`devicePublicBundleToHex` emits a record with `ik_public`, `xdh_public`,
`spk_public`, `spk_signature`, and a list `opk_publics`; `KeyController` maps
the first `opk_public` into the single-opk API field.